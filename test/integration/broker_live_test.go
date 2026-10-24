// Copyright 2026 The external-dns-cloudflare-zerotrust-provider Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build integration

package integration

// A LIVE test of the route broker: the real Go client and provider, through a REAL deployed Worker,
// behind a REAL Cloudflare Access application, to the REAL Cloudflare API. It is what the unit and
// end-to-end tests cannot be: it proves the Worker runs in the Workers runtime, that Access issues
// the JWT the broker expects, and that Cloudflare answers the way the fake does.
//
// It needs a deployed broker and two Access service tokens, which broker/README.md describes. The
// policy it expects is:
//
//	client X: owner cluster-x, tunnel CF_TUNNEL_ID,   suffixes x.broker-spike.private, shared.broker-spike.private
//	client Y: owner cluster-y, tunnel CF_TUNNEL_ID_B, suffixes y.broker-spike.private, shared.broker-spike.private
//
//	export BROKER_URL=https://<the broker>
//	export BROKER_CLIENT_ID_X=... BROKER_CLIENT_SECRET_X=...
//	export BROKER_CLIENT_ID_Y=... BROKER_CLIENT_SECRET_Y=...
//	export CF_ACCOUNT_ID=... CF_TUNNEL_ID=... CF_TUNNEL_ID_B=...
//	go test -tags=integration -v -run TestLiveBroker ./test/integration/
//
// It deliberately never reads CF_API_TOKEN: nothing here may hold the account token.

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"

	"github.com/arustydev/external-dns-cloudflare-zerotrust-provider/internal/cloudflare"
	"github.com/arustydev/external-dns-cloudflare-zerotrust-provider/internal/metrics"
	cfprovider "github.com/arustydev/external-dns-cloudflare-zerotrust-provider/internal/provider"
)

const (
	liveSuffixX      = "x.broker-spike.private"
	liveSuffixShared = "shared.broker-spike.private"
	liveRoutesPath   = "/zerotrust/routes/hostname"
)

func liveBrokerClient(base, account, id, secret string) *cloudflare.Client {
	return cloudflare.New(account, "",
		cloudflare.WithBaseURL(base),
		cloudflare.WithHeader("CF-Access-Client-Id", id),
		cloudflare.WithHeader("CF-Access-Client-Secret", secret))
}

func liveHosts(routes []cloudflare.HostnameRoute) []string {
	var out []string
	for _, r := range routes {
		out = append(out, r.Hostname)
	}
	return out
}

func liveFind(routes []cloudflare.HostnameRoute, host string) (cloudflare.HostnameRoute, bool) {
	for _, r := range routes {
		if r.Hostname == host {
			return r, true
		}
	}
	return cloudflare.HostnameRoute{}, false
}

func TestLiveBrokerThroughAccess(t *testing.T) {
	base := mustEnv(t, "BROKER_URL")
	account := mustEnv(t, "CF_ACCOUNT_ID")
	tunnelA := mustEnv(t, "CF_TUNNEL_ID")
	tunnelB := mustEnv(t, "CF_TUNNEL_ID_B")
	x := liveBrokerClient(base, account, mustEnv(t, "BROKER_CLIENT_ID_X"), mustEnv(t, "BROKER_CLIENT_SECRET_X"))
	y := liveBrokerClient(base, account, mustEnv(t, "BROKER_CLIENT_ID_Y"), mustEnv(t, "BROKER_CLIENT_SECRET_Y"))
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	// Every route this test creates is removed by its own client, whatever happens.
	ownX, heldBy := liveSuffixX, "held."+liveSuffixShared
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), time.Minute)
		defer ccancel()
		for _, c := range []*cloudflare.Client{x, y} {
			routes, err := c.ListHostnameRoutes(cctx, "")
			if err != nil {
				continue
			}
			for _, r := range routes {
				_ = c.DeleteHostnameRoute(cctx, r.ID)
			}
		}
	})

	t.Run("an authenticated list works, which proves the Worker ran and Access issued a JWT it accepts", func(t *testing.T) {
		routes, err := x.ListHostnameRoutes(ctx, "")
		if err != nil {
			t.Fatalf("x list through the broker: %v\n"+
				"(a 401 here means the Worker rejected Access's JWT: check ACCESS_TEAM_DOMAIN, ACCESS_AUD and the policy key)", err)
		}
		t.Logf("OBSERVED x sees %d routes on its fresh tunnel (want 0)", len(routes))
		if len(routes) != 0 {
			t.Errorf("x sees %v on a fresh tunnel", liveHosts(routes))
		}
	})

	t.Run("a request with no service token is refused by Access and never reaches the broker", func(t *testing.T) {
		noRedirect := &http.Client{
			Timeout:       30 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
		res, err := noRedirect.Get(base + "/accounts/" + account + liveRoutesPath)
		if err != nil {
			t.Fatalf("GET without credentials: %v", err)
		}
		_ = res.Body.Close()
		t.Logf("OBSERVED an unauthenticated request got HTTP %d", res.StatusCode)
		if res.StatusCode == http.StatusOK {
			t.Fatal("an unauthenticated request was answered 200")
		}
	})

	t.Run("the provider creates a route through the broker", func(t *testing.T) {
		reg := prometheus.NewRegistry()
		m := metrics.New()
		m.MustRegister(reg)
		p, err := cfprovider.New(cfprovider.Config{
			Client: x, TunnelID: tunnelA, OwnerID: "cluster-x", OwnershipStrict: true,
			DomainFilter: []string{liveSuffixX}, Metrics: m,
			Logger: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		host := "a." + ownX
		if err := p.ApplyChanges(ctx, &plan.Changes{Create: []*endpoint.Endpoint{
			endpoint.NewEndpoint(host, endpoint.RecordTypeCNAME, ""),
		}}); err != nil {
			t.Fatalf("create through the broker: %v", err)
		}
		routes, err := x.ListHostnameRoutes(ctx, "")
		if err != nil {
			t.Fatalf("x list: %v", err)
		}
		r, ok := liveFind(routes, host)
		if !ok || r.TunnelID != tunnelA || r.Comment != "managed-by=external-dns/cluster-x" {
			t.Fatalf("route = %+v (found=%v), want it on tunnel A with x's owner tag", r, ok)
		}
	})

	t.Run("another client cannot see the route, and cannot delete it", func(t *testing.T) {
		theirs, err := y.ListHostnameRoutes(ctx, "")
		if err != nil {
			t.Fatalf("y list: %v", err)
		}
		if _, leaked := liveFind(theirs, "a."+ownX); leaked {
			t.Fatalf("y can see x's route: %v", liveHosts(theirs))
		}

		mine, _ := x.ListHostnameRoutes(ctx, "")
		r, ok := liveFind(mine, "a."+ownX)
		if !ok {
			t.Fatal("x's route is missing")
		}
		err = y.DeleteHostnameRoute(ctx, r.ID)
		var apiErr *cloudflare.APIError
		if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusNotFound || !cloudflare.HasCode(err, 1107) {
			t.Fatalf("y deleting x's route: %v, want 404 / 1107 (indistinguishable from a missing route)", err)
		}
		after, _ := x.ListHostnameRoutes(ctx, "")
		if _, still := liveFind(after, "a."+ownX); !still {
			t.Fatal("y managed to delete x's route")
		}
	})

	t.Run("a client cannot name another client's tunnel, or retarget onto it", func(t *testing.T) {
		_, err := x.ListHostnameRoutes(ctx, tunnelB)
		if !cloudflare.HasCode(err, 9109) {
			t.Errorf("x listing y's tunnel: %v, want 403 / 9109", err)
		}
		mine, _ := x.ListHostnameRoutes(ctx, "")
		r, _ := liveFind(mine, "a."+ownX)
		_, err = x.PatchHostnameRoute(ctx, r.ID, cloudflare.RoutePatch{TunnelID: tunnelB})
		var apiErr *cloudflare.APIError
		if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusForbidden {
			t.Errorf("x retargeting onto y's tunnel: %v, want 403", err)
		}
	})

	t.Run("a hostname another client holds is Cloudflare's own 409, pending and anonymous for the provider", func(t *testing.T) {
		if _, err := y.CreateHostnameRoute(ctx, heldBy, tunnelB, "managed-by=external-dns/cluster-y"); err != nil {
			t.Fatalf("y creates the held hostname: %v", err)
		}
		_, err := x.CreateHostnameRoute(ctx, heldBy, tunnelA, "managed-by=external-dns/cluster-x")
		if !cloudflare.HasCode(err, cloudflare.ErrCodeHostnameAlreadyRouted) {
			t.Fatalf("x creating y's hostname: %v, want Cloudflare's 409 / 1108 passed through", err)
		}

		var logs bytes.Buffer
		p, err := cfprovider.New(cfprovider.Config{
			Client: x, TunnelID: tunnelA, OwnerID: "cluster-x", OwnershipStrict: true,
			DomainFilter: []string{liveSuffixShared},
			Logger:       slog.New(slog.NewTextHandler(&logs, nil)),
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if err := p.ApplyChanges(ctx, &plan.Changes{Create: []*endpoint.Endpoint{
			endpoint.NewEndpoint(heldBy, endpoint.RecordTypeCNAME, ""),
		}}); err != nil {
			t.Fatalf("a held hostname must be pending, not an error: %v", err)
		}
		for _, leaked := range []string{tunnelB, "cluster-y"} {
			if bytes.Contains(logs.Bytes(), []byte(leaked)) {
				t.Errorf("something about the holder leaked into the provider's log: %q", leaked)
			}
		}
	})

	t.Run("each client deletes its own routes", func(t *testing.T) {
		for name, c := range map[string]*cloudflare.Client{"x": x, "y": y} {
			routes, err := c.ListHostnameRoutes(ctx, "")
			if err != nil {
				t.Fatalf("%s list: %v", name, err)
			}
			for _, r := range routes {
				if err := c.DeleteHostnameRoute(ctx, r.ID); err != nil {
					t.Errorf("%s deleting its own %s: %v", name, r.Hostname, err)
				}
			}
		}
	})
}
