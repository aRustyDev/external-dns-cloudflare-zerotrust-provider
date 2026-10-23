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

import (
	"context"
	"testing"
	"time"

	"github.com/arustydev/external-dns-cloudflare-zerotrust-provider/internal/cloudflare"
)

// TestLiveScopedTokenHostnameRoutes is the go/no-go for per-tunnel token isolation.
//
// Cloudflare's granular tunnel permissions name Tunnels, Mesh nodes and the teamnet/routes listing
// as enforced resources, but do not mention zerotrust/routes/hostname. This test finds out what a
// token bound to ONE tunnel can actually do to hostname routes, including routes on a tunnel it
// has no rights over.
//
// Needs, in addition to the usual variables:
//
//	CF_TUNNEL_ID_B          a second throwaway tunnel, which the scoped token must NOT cover
//	CF_API_TOKEN_SCOPED     an Account API Token bound to a tunnel-scoped write role on tunnel A
//	                        only, with NO account-level Cloudflare One / Tunnel role
//
// CF_API_TOKEN (the unscoped one) is used only to set up and clean up fixtures. Every call made
// with the scoped token is logged as an OBSERVED line and none of them fails the test: a refusal is
// the finding. The foreign route on tunnel B is deleted by the scoped token as the LAST step, so
// if isolation is absent it is destroyed. That is why this needs a throwaway tunnel.
func TestLiveScopedTokenHostnameRoutes(t *testing.T) {
	acct := mustEnv(t, "CF_ACCOUNT_ID")
	adminToken := mustEnv(t, "CF_API_TOKEN")
	scopedToken := mustEnv(t, "CF_API_TOKEN_SCOPED")
	tunnelA := mustEnv(t, "CF_TUNNEL_ID")
	tunnelB := mustEnv(t, "CF_TUNNEL_ID_B")
	if tunnelA == tunnelB {
		t.Skip("CF_TUNNEL_ID and CF_TUNNEL_ID_B must name two different tunnels")
	}
	admin := cloudflare.New(acct, adminToken)
	scoped := cloudflare.New(acct, scopedToken)
	const comment = "managed-by=external-dns/integration-test"
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// Fixture: a route on tunnel B that the scoped token has no business touching.
	heldOnB := uniqueHost(t, "held-b")
	foreign, err := admin.CreateHostnameRoute(ctx, heldOnB, tunnelB, comment)
	if err != nil {
		t.Fatalf("fixture: create %q on tunnel B with the unscoped token: %v", heldOnB, err)
	}
	cleanupHost(t, admin, heldOnB, tunnelA, tunnelB)

	// Listing: what can the scoped token see?
	all, err := scoped.ListHostnameRoutes(ctx, "")
	observe(t, "scoped list, whole account", err)
	if err == nil {
		t.Logf("OBSERVED scoped list, whole account: %d routes; includes tunnel B's fixture: %v",
			len(all), activeHost(all, heldOnB))
	}
	onA, err := scoped.ListHostnameRoutes(ctx, tunnelA)
	observe(t, "scoped list, tunnel A", err)
	if err == nil {
		t.Logf("OBSERVED scoped list, tunnel A: %d routes", len(onA))
	}
	onB, err := scoped.ListHostnameRoutes(ctx, tunnelB)
	observe(t, "scoped list, tunnel B", err)
	if err == nil {
		t.Logf("OBSERVED scoped list, tunnel B: %d routes; includes the fixture: %v", len(onB), activeHost(onB, heldOnB))
	}

	// Creating: on its own tunnel, on a tunnel it does not cover, and for a hostname already held.
	ownHost := uniqueHost(t, "own-a")
	_, err = scoped.CreateHostnameRoute(ctx, ownHost, tunnelA, comment)
	observe(t, "scoped create, new hostname on tunnel A", err)
	cleanupHost(t, admin, ownHost, tunnelA, tunnelB)

	elsewhere := uniqueHost(t, "new-b")
	_, err = scoped.CreateHostnameRoute(ctx, elsewhere, tunnelB, comment)
	observe(t, "scoped create, new hostname on tunnel B", err)
	cleanupHost(t, admin, elsewhere, tunnelA, tunnelB)

	_, err = scoped.CreateHostnameRoute(ctx, heldOnB, tunnelA, comment)
	observe(t, "scoped create, hostname already held on tunnel B", err)

	// Modifying a route on a tunnel the token does not cover.
	_, err = scoped.PatchHostnameRouteComment(ctx, foreign.ID, "tampered with by the scoped token")
	observe(t, "scoped PATCH of a route on tunnel B", err)

	// Destructive, so last. If this succeeds there is no isolation.
	err = scoped.DeleteHostnameRoute(ctx, foreign.ID)
	observe(t, "scoped DELETE of a route on tunnel B", err)
}
