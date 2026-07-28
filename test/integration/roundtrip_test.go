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

// Package integration holds LIVE tests that talk to the real Cloudflare Zero Trust API.
// They are gated behind the `integration` build tag so `go test ./...` never runs them.
//
// Run against a THROWAWAY tunnel with a scoped token (Account > Cloudflare Tunnel : Edit):
//
//	export CF_API_TOKEN=...        # scoped token, deletable
//	export CF_ACCOUNT_ID=...
//	export CF_TUNNEL_ID=...        # a throwaway tunnel
//	# optional: export INTEGRATION_HOSTNAME=extdns-cfzt-it.private
//	go test -tags=integration -v -run TestLive ./test/integration/
//
// Each test creates a uniquely-named route, asserts the round-trip, and cleans up after
// itself (t.Cleanup) even on failure. Nothing here is committed with real credentials.
package integration

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/arustydev/external-dns-cloudflare-zerotrust-provider/internal/cloudflare"
	cfprovider "github.com/arustydev/external-dns-cloudflare-zerotrust-provider/internal/provider"
	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"
)

func mustEnv(t *testing.T, key string) string {
	t.Helper()
	v := os.Getenv(key)
	if v == "" {
		t.Skipf("%s not set; skipping live integration test", key)
	}
	return v
}

func testHost(t *testing.T) string {
	if h := os.Getenv("INTEGRATION_HOSTNAME"); h != "" {
		return h
	}
	return fmt.Sprintf("extdns-cfzt-it-%d.private", time.Now().UnixNano())
}

// activeHost reports whether an un-deleted route for host exists in routes.
func activeHost(routes []cloudflare.HostnameRoute, host string) bool {
	for _, r := range routes {
		if r.Hostname == host && r.DeletedAt == nil {
			return true
		}
	}
	return false
}

// TestLiveClientRoundTrip exercises the raw Cloudflare client: create -> list(present) ->
// delete -> list(absent).
func TestLiveClientRoundTrip(t *testing.T) {
	acct := mustEnv(t, "CF_ACCOUNT_ID")
	token := mustEnv(t, "CF_API_TOKEN")
	tunnel := mustEnv(t, "CF_TUNNEL_ID")
	host := testHost(t)

	c := cloudflare.New(acct, token)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	created, err := c.CreateHostnameRoute(ctx, host, tunnel, "managed-by=external-dns/integration-test")
	if err != nil {
		t.Fatalf("create %q: %v", host, err)
	}
	t.Logf("created route id=%s hostname=%s", created.ID, created.Hostname)
	t.Cleanup(func() { _ = c.DeleteHostnameRoute(context.Background(), created.ID) })

	routes, err := c.ListHostnameRoutes(ctx, tunnel)
	if err != nil {
		t.Fatalf("list after create: %v", err)
	}
	if !activeHost(routes, host) {
		t.Fatalf("route %q not present after create", host)
	}

	if err := c.DeleteHostnameRoute(ctx, created.ID); err != nil {
		t.Fatalf("delete %q: %v", host, err)
	}

	routes, err = c.ListHostnameRoutes(ctx, tunnel)
	if err != nil {
		t.Fatalf("list after delete: %v", err)
	}
	if activeHost(routes, host) {
		t.Fatalf("route %q still active after delete", host)
	}
}

// TestLiveProviderApplyChanges exercises the full provider path against the live API:
// ApplyChanges(create) -> Records(shows it) -> ApplyChanges(delete) -> Records(empty).
// Runs in ownership-strict mode with a dedicated owner so it only ever sees/deletes its own
// route and cannot disturb anything else on the tunnel.
func TestLiveProviderApplyChanges(t *testing.T) {
	acct := mustEnv(t, "CF_ACCOUNT_ID")
	token := mustEnv(t, "CF_API_TOKEN")
	tunnel := mustEnv(t, "CF_TUNNEL_ID")
	host := testHost(t)

	client := cloudflare.New(acct, token)
	p, err := cfprovider.New(cfprovider.Config{
		Client:          client,
		TunnelID:        tunnel,
		OwnerID:         "integration-test",
		OwnershipStrict: true,
		DomainFilter:    []string{"private"},
	})
	if err != nil {
		t.Fatalf("New provider: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	target := host // target value is irrelevant; provider canonicalizes to the tunnel target
	create := &plan.Changes{Create: []*endpoint.Endpoint{
		endpoint.NewEndpoint(host, endpoint.RecordTypeCNAME, target),
	}}
	if err := p.ApplyChanges(ctx, create); err != nil {
		t.Fatalf("ApplyChanges(create): %v", err)
	}
	// Best-effort cleanup via the raw client in case a later assertion fails.
	t.Cleanup(func() {
		routes, _ := client.ListHostnameRoutes(context.Background(), tunnel)
		for _, r := range routes {
			if r.Hostname == host && r.DeletedAt == nil {
				_ = client.DeleteHostnameRoute(context.Background(), r.ID)
			}
		}
	})

	eps, err := p.Records(ctx)
	if err != nil {
		t.Fatalf("Records after create: %v", err)
	}
	if !hasEndpoint(eps, host) {
		t.Fatalf("provider Records does not include %q after create", host)
	}

	del := &plan.Changes{Delete: []*endpoint.Endpoint{
		endpoint.NewEndpoint(host, endpoint.RecordTypeCNAME, target),
	}}
	if err := p.ApplyChanges(ctx, del); err != nil {
		t.Fatalf("ApplyChanges(delete): %v", err)
	}

	eps, err = p.Records(ctx)
	if err != nil {
		t.Fatalf("Records after delete: %v", err)
	}
	if hasEndpoint(eps, host) {
		t.Fatalf("provider Records still includes %q after delete", host)
	}
}

func hasEndpoint(eps []*endpoint.Endpoint, host string) bool {
	for _, e := range eps {
		if e.DNSName == host {
			return true
		}
	}
	return false
}
