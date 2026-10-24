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

// Live tests for the multi-tunnel lifecycle: retargeting a route between tunnels in place.
//
// They need TWO throwaway tunnels in the same account, in addition to the variables the other live
// tests read:
//
//	export CF_TUNNEL_ID=...      # tunnel A
//	export CF_TUNNEL_ID_B=...    # tunnel B
//
// Each test creates a uniquely named route, cleans it up on every exit path, and skips with a clear
// message when a variable is missing.

import (
	"context"
	"testing"
	"time"

	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"

	"github.com/arustydev/external-dns-cloudflare-zerotrust-provider/internal/cloudflare"
	cfprovider "github.com/arustydev/external-dns-cloudflare-zerotrust-provider/internal/provider"
)

// twoTunnelEnv returns a client and the ids of the two throwaway tunnels, or skips the test.
func twoTunnelEnv(t *testing.T) (*cloudflare.Client, string, string) {
	t.Helper()
	acct := mustEnv(t, "CF_ACCOUNT_ID")
	token := mustEnv(t, "CF_API_TOKEN")
	a := mustEnv(t, "CF_TUNNEL_ID")
	b := mustEnv(t, "CF_TUNNEL_ID_B")
	if a == b {
		t.Skip("CF_TUNNEL_ID and CF_TUNNEL_ID_B must name two different tunnels")
	}
	return cloudflare.New(acct, token), a, b
}

// routeOn returns the live route for host on the given tunnel, if there is one.
func routeOn(ctx context.Context, t *testing.T, c *cloudflare.Client, tunnel, host string) (cloudflare.HostnameRoute, bool) {
	t.Helper()
	routes, err := c.ListHostnameRoutes(ctx, tunnel)
	if err != nil {
		t.Fatalf("list tunnel %s: %v", tunnel, err)
	}
	for _, r := range routes {
		if r.Hostname == host && r.DeletedAt == nil {
			return r, true
		}
	}
	return cloudflare.HostnameRoute{}, false
}

// cleanupHost deletes every live route for host on the given tunnels, however the test ends.
func cleanupHost(t *testing.T, c *cloudflare.Client, host string, tunnels ...string) {
	t.Helper()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		for _, tunnel := range tunnels {
			routes, err := c.ListHostnameRoutes(ctx, tunnel)
			if err != nil {
				continue
			}
			for _, r := range routes {
				if r.Hostname == host && r.DeletedAt == nil {
					_ = c.DeleteHostnameRoute(ctx, r.ID)
				}
			}
		}
	})
}

// TestLiveRetargetPreservesRouteID settles the central assumption behind in-place retargeting: a
// PATCH carrying tunnel_id moves the route to the other tunnel and the route keeps its id, so the
// hostname is never unrouted. It sends the documented full body.
//
// It then PATCHes tunnel_id ALONE and only LOGS what happened. Whether a partial body is accepted
// is an open question, not a requirement, and the provider does not depend on it.
func TestLiveRetargetPreservesRouteID(t *testing.T) {
	c, tunnelA, tunnelB := twoTunnelEnv(t)
	host := testHost(t)
	const comment = "managed-by=external-dns/integration-test"
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	created, err := c.CreateHostnameRoute(ctx, host, tunnelA, comment)
	requireCreate(t, "create "+host+" on tunnel A", err)
	cleanupHost(t, c, host, tunnelA, tunnelB)
	t.Logf("created route id=%s on tunnel A", created.ID)

	patched, err := c.PatchHostnameRoute(ctx, created.ID, cloudflare.RoutePatch{
		Hostname: host, TunnelID: tunnelB, Comment: comment,
	})
	if err != nil {
		t.Fatalf("PATCH {hostname, tunnel_id, comment}: %v", err)
	}
	if patched.ID != created.ID {
		t.Errorf("the route id changed across the retarget: %s -> %s", created.ID, patched.ID)
	}
	if patched.TunnelID != tunnelB {
		t.Errorf("PATCH response says tunnel %s, want tunnel B %s", patched.TunnelID, tunnelB)
	}

	onB, found := routeOn(ctx, t, c, tunnelB, host)
	if !found || onB.ID != created.ID {
		t.Errorf("after the retarget tunnel B lists %+v (found=%v), want route %s", onB, found, created.ID)
	}
	if _, still := routeOn(ctx, t, c, tunnelA, host); still {
		t.Error("the route is still listed on tunnel A after the retarget")
	}

	// Observation only.
	back, err := c.PatchHostnameRoute(ctx, created.ID, cloudflare.RoutePatch{TunnelID: tunnelA})
	if err != nil {
		t.Logf("OBSERVED: a tunnel_id-only PATCH is rejected: %v", err)
		return
	}
	t.Logf("OBSERVED: a tunnel_id-only PATCH is accepted: id=%s tunnel=%s (asked for %s)", back.ID, back.TunnelID, tunnelA)
}

// TestLiveProviderRetargetsFromADrainingTunnel runs the whole path against the live API with the
// real ExternalDNS planner in the middle: a route sits on tunnel A, the provider serves the domain
// from tunnel B and lists A as draining, and one reconcile moves the route without changing its id.
func TestLiveProviderRetargetsFromADrainingTunnel(t *testing.T) {
	c, tunnelA, tunnelB := twoTunnelEnv(t)
	host := testHost(t)
	suffix := testDomainFilter(t)
	const owner = "integration-test"
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	created, err := c.CreateHostnameRoute(ctx, host, tunnelA, "managed-by=external-dns/"+owner)
	requireCreate(t, "create "+host+" on tunnel A", err)
	cleanupHost(t, c, host, tunnelA, tunnelB)

	p, err := cfprovider.New(cfprovider.Config{
		Client:          c,
		TunnelMap:       map[string]string{suffix: tunnelB},
		TunnelDrain:     []string{tunnelA},
		OwnerID:         owner,
		OwnershipStrict: true,
		DomainFilter:    []string{suffix},
	})
	if err != nil {
		t.Fatalf("New provider: %v", err)
	}

	current, err := p.Records(ctx)
	if err != nil {
		t.Fatalf("Records: %v", err)
	}
	if !hasEndpoint(current, host) {
		t.Fatalf("Records does not report %q on the draining tunnel", host)
	}
	desired, err := p.AdjustEndpoints([]*endpoint.Endpoint{endpoint.NewEndpoint(host, endpoint.RecordTypeA, "10.0.0.5")})
	if err != nil {
		t.Fatalf("AdjustEndpoints: %v", err)
	}
	calculated := (&plan.Plan{
		Policies:       []plan.Policy{&plan.SyncPolicy{}},
		Current:        current,
		Desired:        desired,
		ManagedRecords: []string{endpoint.RecordTypeCNAME},
	}).Calculate()
	if len(calculated.Changes.UpdateNew) != 1 {
		t.Fatalf("plan = %+v, want exactly one update", calculated.Changes)
	}
	if err := p.ApplyChanges(ctx, calculated.Changes); err != nil {
		t.Fatalf("ApplyChanges: %v", err)
	}

	onB, found := routeOn(ctx, t, c, tunnelB, host)
	if !found || onB.ID != created.ID {
		t.Fatalf("after one reconcile tunnel B lists %+v (found=%v), want route %s", onB, found, created.ID)
	}
	if _, still := routeOn(ctx, t, c, tunnelA, host); still {
		t.Error("the route is still on the draining tunnel")
	}
}
