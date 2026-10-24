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

// Package broker_test drives the REAL Go client and provider against the REAL broker handler, with
// only Cloudflare itself faked. The broker is TypeScript, so a small Node server (broker/e2e)
// hosts it; the tests skip when Node is not available.
//
// What this catches that the unit tests on each side cannot: a contract mismatch between the two,
// such as the provider writing a comment tag the broker's policy refuses, or an error envelope the
// Go client cannot decode.
package broker_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"

	"github.com/arustydev/external-dns-cloudflare-zerotrust-provider/internal/cloudflare"
	"github.com/arustydev/external-dns-cloudflare-zerotrust-provider/internal/metrics"
	cfprovider "github.com/arustydev/external-dns-cloudflare-zerotrust-provider/internal/provider"
)

// These mirror broker/test/support.ts.
const (
	account = "acct1"
	tunnelA = "aaaaaaaa-0000-0000-0000-00000000000a" // client x
	tunnelB = "bbbbbbbb-0000-0000-0000-00000000000b" // client y
	tunnelC = "bbbbbbbb-0000-0000-0000-0000000000b2" // client y, a second tunnel

	idFoo  = "a1a1a1a1-0000-0000-0000-000000000001" // foo.x.woven on tunnel A
	idBar  = "b1b1b1b1-0000-0000-0000-000000000001" // bar.y.woven on tunnel B
	idHeld = "b2b2b2b2-0000-0000-0000-000000000002" // held.shared.woven on tunnel B
	idNone = "deadbeef-0000-0000-0000-000000000000" // does not exist
)

type server struct {
	base string
}

// startBroker runs broker/e2e/serve.ts and returns its address, or skips the test.
func startBroker(t *testing.T) *server {
	t.Helper()
	out, err := exec.Command("node", "--version").Output()
	if err != nil {
		t.Skip("node is not installed; skipping the broker end-to-end test")
	}
	m := regexp.MustCompile(`^v(\d+)\.(\d+)`).FindStringSubmatch(strings.TrimSpace(string(out)))
	if m == nil {
		t.Skipf("cannot read the node version %q", out)
	}
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	if major < 23 || (major == 23 && minor < 6) {
		t.Skipf("node %s cannot run TypeScript directly (needs 23.6 or newer)", strings.TrimSpace(string(out)))
	}

	cmd := exec.Command("node", "broker/e2e/serve.ts")
	cmd.Dir = "../.."
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start node: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	port := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			if p, ok := strings.CutPrefix(sc.Text(), "LISTENING "); ok {
				port <- p
				return
			}
		}
		close(port)
	}()
	select {
	case p, ok := <-port:
		if !ok {
			t.Fatalf("the broker server exited before listening: %s", stderr.String())
		}
		return &server{base: "http://127.0.0.1:" + p}
	case <-time.After(20 * time.Second):
		t.Fatalf("the broker server did not start: %s", stderr.String())
	}
	return nil
}

// as returns a client that authenticates the way a deployed instance does: Access service-token
// headers and no bearer token. The test server treats the client id header as the identity.
func (s *server) as(clientID string) *cloudflare.Client {
	opts := []cloudflare.Option{cloudflare.WithBaseURL(s.base)}
	if clientID != "" {
		opts = append(opts,
			cloudflare.WithHeader("CF-Access-Client-Id", clientID),
			cloudflare.WithHeader("CF-Access-Client-Secret", "not-checked-by-the-test-server"))
	}
	return cloudflare.New(account, "", opts...)
}

func (s *server) state(t *testing.T) []cloudflare.HostnameRoute {
	t.Helper()
	return getJSON[[]cloudflare.HostnameRoute](t, s.base+"/__state")
}

func getJSON[T any](t *testing.T, url string) T {
	t.Helper()
	res, err := http.Get(url) //nolint:gosec // a local test server
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = res.Body.Close() }()
	body, _ := io.ReadAll(res.Body)
	var v T
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatalf("decode %s: %v\n%s", url, err, body)
	}
	return v
}

func hostnames(routes []cloudflare.HostnameRoute) []string {
	var out []string
	for _, r := range routes {
		out = append(out, r.Hostname)
	}
	return out
}

func routeFor(routes []cloudflare.HostnameRoute, host string) (cloudflare.HostnameRoute, bool) {
	for _, r := range routes {
		if r.Hostname == host {
			return r, true
		}
	}
	return cloudflare.HostnameRoute{}, false
}

func TestBroker_AClientSeesOnlyItsOwnRoutes(t *testing.T) {
	s := startBroker(t)
	ctx := context.Background()

	mine, err := s.as("x").ListHostnameRoutes(ctx, "")
	if err != nil {
		t.Fatalf("x list: %v", err)
	}
	if got := hostnames(mine); len(got) != 1 || got[0] != "foo.x.woven" {
		t.Errorf("x sees %v, want only foo.x.woven (nothing of y's, nothing orphaned)", got)
	}

	theirs, err := s.as("y").ListHostnameRoutes(ctx, "")
	if err != nil {
		t.Fatalf("y list: %v", err)
	}
	if len(theirs) != 2 {
		t.Errorf("y sees %v, want its own two routes", hostnames(theirs))
	}

	// Naming a tunnel it does not hold is refused outright, as Cloudflare's own envelope.
	_, err = s.as("x").ListHostnameRoutes(ctx, tunnelB)
	var apiErr *cloudflare.APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusForbidden || !cloudflare.HasCode(err, 9109) {
		t.Errorf("listing a foreign tunnel: %v, want 403 / 9109 decoded by the real client", err)
	}
}

func TestBroker_AForeignRouteLooksExactlyLikeAMissingOne(t *testing.T) {
	s := startBroker(t)
	ctx := context.Background()
	x := s.as("x")

	foreign := x.DeleteHostnameRoute(ctx, idBar)
	missing := x.DeleteHostnameRoute(ctx, idNone)
	for name, err := range map[string]error{"foreign": foreign, "missing": missing} {
		var apiErr *cloudflare.APIError
		if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusNotFound || !cloudflare.HasCode(err, 1107) {
			t.Errorf("%s route: %v, want 404 / 1107", name, err)
		}
	}
	if foreign.Error() != strings.ReplaceAll(missing.Error(), idNone, idBar) {
		t.Errorf("the two refusals differ:\n  foreign: %v\n  missing: %v", foreign, missing)
	}
	if _, ok := routeFor(s.state(t), "bar.y.woven"); !ok {
		t.Error("x managed to delete y's route")
	}

	_, err := x.PatchHostnameRouteComment(ctx, idHeld, "managed-by=external-dns/cluster-x")
	if !cloudflare.HasCode(err, 1107) {
		t.Errorf("patching a foreign route: %v, want 404 / 1107", err)
	}
}

func TestBroker_AnUnauthenticatedCallIsRefused(t *testing.T) {
	s := startBroker(t)
	_, err := s.as("").ListHostnameRoutes(context.Background(), "")
	var apiErr *cloudflare.APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusUnauthorized {
		t.Fatalf("an unauthenticated list: %v, want 401", err)
	}
}

// The upstream account token belongs to the broker alone. The caller's credentials must never be
// forwarded, and the account token must never be sent anywhere but upstream.
func TestBroker_UpstreamOnlyEverSeesTheBrokersOwnCredential(t *testing.T) {
	s := startBroker(t)
	if _, err := s.as("x").ListHostnameRoutes(context.Background(), ""); err != nil {
		t.Fatalf("list: %v", err)
	}
	calls := getJSON[[]struct {
		Authorization string `json:"authorization"`
	}](t, s.base+"/__calls")
	if len(calls) == 0 {
		t.Fatal("the upstream saw no calls")
	}
	for _, c := range calls {
		if c.Authorization != "Bearer UPSTREAM-ACCOUNT-TOKEN" {
			t.Errorf("an upstream call carried Authorization %q, want only the broker's own token", c.Authorization)
		}
	}
}

func providerFor(t *testing.T, s *server, clientID string, cfg cfprovider.Config) (*cfprovider.Provider, *prometheus.Registry, *bytes.Buffer) {
	t.Helper()
	reg := prometheus.NewRegistry()
	m := metrics.New()
	m.MustRegister(reg)
	var logs bytes.Buffer
	cfg.Client = s.as(clientID)
	cfg.OwnershipStrict = true
	cfg.Metrics = m
	cfg.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	p, err := cfprovider.New(cfg)
	if err != nil {
		t.Fatalf("New provider: %v", err)
	}
	return p, reg, &logs
}

func cname(host string) *endpoint.Endpoint {
	return endpoint.NewEndpoint(host, endpoint.RecordTypeCNAME, "")
}

// The provider's whole create, list and delete cycle through the broker. It also proves that the
// comment tag the provider writes is the one the broker's policy requires of this owner.
func TestBroker_TheProviderCreatesListsAndDeletesThroughIt(t *testing.T) {
	s := startBroker(t)
	ctx := context.Background()
	p, _, _ := providerFor(t, s, "x", cfprovider.Config{
		TunnelID: tunnelA, OwnerID: "cluster-x", DomainFilter: []string{"x.woven"},
	})

	if err := p.ApplyChanges(ctx, &plan.Changes{Create: []*endpoint.Endpoint{cname("new.x.woven")}}); err != nil {
		t.Fatalf("create through the broker: %v", err)
	}
	r, ok := routeFor(s.state(t), "new.x.woven")
	if !ok || r.TunnelID != tunnelA || r.Comment != "managed-by=external-dns/cluster-x" {
		t.Fatalf("created route = %+v (found=%v), want it on tunnel A with the owner tag", r, ok)
	}

	eps, err := p.Records(ctx)
	if err != nil {
		t.Fatalf("Records: %v", err)
	}
	var seen []string
	for _, e := range eps {
		seen = append(seen, e.DNSName)
	}
	if len(seen) != 2 { // foo.x.woven and new.x.woven, both x's and both tagged
		t.Errorf("Records = %v, want x's two routes", seen)
	}

	if err := p.ApplyChanges(ctx, &plan.Changes{Delete: []*endpoint.Endpoint{cname("new.x.woven")}}); err != nil {
		t.Fatalf("delete through the broker: %v", err)
	}
	if _, ok := routeFor(s.state(t), "new.x.woven"); ok {
		t.Error("the route survived its delete")
	}
	if _, ok := routeFor(s.state(t), "bar.y.woven"); !ok {
		t.Error("another client's route disappeared")
	}
}

// A hostname another client holds comes back as Cloudflare's own 409 / 1108. Through the broker the
// provider must treat it as pending (not an error), and nothing about the holder may reach it.
func TestBroker_AConflictIsPendingAndRevealsNothingAboutTheHolder(t *testing.T) {
	s := startBroker(t)
	ctx := context.Background()
	p, reg, logs := providerFor(t, s, "x", cfprovider.Config{
		TunnelID: tunnelA, OwnerID: "cluster-x", DomainFilter: []string{"x.woven", "shared.woven"},
	})

	// Directly: the real client decodes the broker's pass-through of Cloudflare's conflict.
	_, err := s.as("x").CreateHostnameRoute(ctx, "held.shared.woven", tunnelA, "managed-by=external-dns/cluster-x")
	if !cloudflare.HasCode(err, cloudflare.ErrCodeHostnameAlreadyRouted) {
		t.Fatalf("direct create of a held hostname: %v, want 409 / 1108", err)
	}

	if err := p.ApplyChanges(ctx, &plan.Changes{Create: []*endpoint.Endpoint{cname("held.shared.woven")}}); err != nil {
		t.Fatalf("a held hostname must be pending, not an error: %v", err)
	}
	// The account-wide lookup the classifier makes returns only x's own routes, so the holder is
	// unknown to it, which is the point.
	if got := pendingGauge(t, reg, "unknown"); got != 1 {
		t.Errorf("routes_pending{unknown} = %v, want 1", got)
	}
	for _, leaked := range []string{tunnelB, "cluster-y", "bar.y.woven", idHeld} {
		if strings.Contains(logs.String(), leaked) || strings.Contains(err.Error(), leaked) {
			t.Errorf("something about the holder leaked: %q", leaked)
		}
	}
	if _, ok := routeFor(s.state(t), "held.shared.woven"); !ok {
		t.Fatal("the holder's route vanished")
	}
}

// Retargeting (Phase 2a) through the broker, using ExternalDNS's real planner: y's route moves from
// its draining tunnel to its new one with a PATCH the broker authorizes because both tunnels are y's.
func TestBroker_ARetargetBetweenTheClientsOwnTunnelsGoesThrough(t *testing.T) {
	s := startBroker(t)
	ctx := context.Background()
	p, _, _ := providerFor(t, s, "y", cfprovider.Config{
		TunnelMap: map[string]string{"y.woven": tunnelC}, TunnelDrain: []string{tunnelB},
		OwnerID: "cluster-y", DomainFilter: []string{"y.woven"},
	})

	current, err := p.Records(ctx)
	if err != nil {
		t.Fatalf("Records: %v", err)
	}
	desired, err := p.AdjustEndpoints([]*endpoint.Endpoint{endpoint.NewEndpoint("bar.y.woven", endpoint.RecordTypeA, "10.0.0.5")})
	if err != nil {
		t.Fatalf("AdjustEndpoints: %v", err)
	}
	changes := (&plan.Plan{
		Policies: []plan.Policy{&plan.SyncPolicy{}}, Current: current, Desired: desired,
		ManagedRecords: []string{endpoint.RecordTypeCNAME},
	}).Calculate().Changes
	if len(changes.UpdateNew) != 1 {
		t.Fatalf("plan = %+v, want exactly one update", changes)
	}
	if err := p.ApplyChanges(ctx, changes); err != nil {
		t.Fatalf("ApplyChanges through the broker: %v", err)
	}
	r, ok := routeFor(s.state(t), "bar.y.woven")
	if !ok || r.ID != idBar || r.TunnelID != tunnelC {
		t.Fatalf("route = %+v (found=%v), want the same id moved to tunnel C", r, ok)
	}
}

// And the broker refuses the same PATCH when it would move a route onto a tunnel the client does
// not hold, whatever the client is configured to want.
func TestBroker_RetargetOntoAForeignTunnelIsRefused(t *testing.T) {
	s := startBroker(t)
	_, err := s.as("x").PatchHostnameRoute(context.Background(), idFoo, cloudflare.RoutePatch{TunnelID: tunnelB})
	var apiErr *cloudflare.APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusForbidden {
		t.Fatalf("retarget onto a foreign tunnel: %v, want 403", err)
	}
	if r, _ := routeFor(s.state(t), "foo.x.woven"); r.TunnelID != tunnelA {
		t.Errorf("the route moved to %s despite the refusal", r.TunnelID)
	}
}

func pendingGauge(t *testing.T, reg *prometheus.Registry, reason string) float64 {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range families {
		if mf.GetName() != "cfzt_provider_routes_pending" {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetName() == "reason" && lp.GetValue() == reason {
					return m.GetGauge().GetValue()
				}
			}
		}
	}
	return 0
}
