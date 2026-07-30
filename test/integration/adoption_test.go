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
	cfprovider "github.com/arustydev/external-dns-cloudflare-zerotrust-provider/internal/provider"
	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"
)

// TestLiveAdoptUntaggedRoute proves against the REAL Cloudflare API that adoption is an in-place
// ownership transfer: an existing untagged route (standing in for a Terraform-owned one) is
// claimed by rewriting only its comment, and the ROUTE ID DOES NOT CHANGE.
//
// The unchanged route id is the whole point. A delete/recreate would also end with a correctly
// tagged route, but it would drop the hostname->tunnel binding in between — an NXDOMAIN window
// per migrated host. Asserting on the id is what distinguishes the two.
//
// Requires a THROWAWAY tunnel: it creates and mutates a route (uniquely named, cleaned up).
func TestLiveAdoptUntaggedRoute(t *testing.T) {
	acct := mustEnv(t, "CF_ACCOUNT_ID")
	token := mustEnv(t, "CF_API_TOKEN")
	tunnel := mustEnv(t, "CF_TUNNEL_ID")
	host := testHost(t)

	client := cloudflare.New(acct, token)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	// Stand in for a route some other system owns: a comment carrying no managed-by tag.
	const foreignComment = "managed by opentofu"
	pre, err := client.CreateHostnameRoute(ctx, host, tunnel, foreignComment)
	if err != nil {
		t.Fatalf("seed untagged route %q: %v", host, err)
	}
	t.Logf("seeded untagged route id=%s hostname=%s comment=%q", pre.ID, pre.Hostname, foreignComment)
	t.Cleanup(func() {
		routes, _ := client.ListHostnameRoutes(context.Background(), tunnel)
		for _, r := range routes {
			if r.Hostname == host && r.DeletedAt == nil {
				_ = client.DeleteHostnameRoute(context.Background(), r.ID)
			}
		}
	})

	p, err := cfprovider.New(cfprovider.Config{
		Client:          client,
		TunnelID:        tunnel,
		OwnerID:         "integration-test",
		OwnershipStrict: true,
		AdoptUntagged:   true,
		DomainFilter:    []string{testDomainFilter(t)},
	})
	if err != nil {
		t.Fatalf("New provider: %v", err)
	}

	// In strict mode the seeded route is INVISIBLE to Records (we do not own it), so external-dns
	// would plan a CREATE for a hostname that already exists. That is precisely the collision
	// adoption resolves — and Cloudflare would otherwise reject the create with 409 / 1108.
	before, err := p.Records(ctx)
	if err != nil {
		t.Fatalf("Records before adoption: %v", err)
	}
	if hasEndpoint(before, host) {
		t.Fatalf("strict-mode Records already sees %q; the seed did not look foreign", host)
	}

	create := &plan.Changes{Create: []*endpoint.Endpoint{
		endpoint.NewEndpoint(host, endpoint.RecordTypeCNAME, host),
	}}
	if err := p.ApplyChanges(ctx, create); err != nil {
		t.Fatalf("ApplyChanges(create) should ADOPT the existing route, not fail: %v", err)
	}

	// Re-read from the API and locate the live route for this hostname.
	routes, err := client.ListHostnameRoutes(ctx, tunnel)
	if err != nil {
		t.Fatalf("list after adoption: %v", err)
	}
	var live []cloudflare.HostnameRoute
	for _, r := range routes {
		if r.Hostname == host && r.DeletedAt == nil {
			live = append(live, r)
		}
	}
	if len(live) != 1 {
		t.Fatalf("want exactly 1 live route for %q after adoption, got %d (%+v)", host, len(live), live)
	}
	got := live[0]

	// THE assertion: same route id => no delete/recreate => no DNS interruption.
	if got.ID != pre.ID {
		t.Errorf("route id changed %s -> %s: adoption must claim in place, not recreate", pre.ID, got.ID)
	}
	if got.TunnelID != tunnel {
		t.Errorf("tunnel binding changed to %s, want %s", got.TunnelID, tunnel)
	}
	if got.Comment != "managed-by=external-dns/integration-test" {
		t.Errorf("comment = %q, want this owner's tag", got.Comment)
	}

	// And the adopted route is now visible to strict-mode Records — ownership really moved.
	after, err := p.Records(ctx)
	if err != nil {
		t.Fatalf("Records after adoption: %v", err)
	}
	if !hasEndpoint(after, host) {
		t.Errorf("strict-mode Records does not include %q after adoption: %v", host, endpointNames(after))
	}
}

// TestLiveDuplicateHostnameIsRejected pins the Cloudflare behaviour the adoption design rests on:
// a duplicate hostname route is REJECTED (409 / ErrCodeHostnameAlreadyRouted), never silently
// double-created. If Cloudflare ever changes this, adoption's premise changes with it — so this
// belongs in CI rather than in a one-off probe.
func TestLiveDuplicateHostnameIsRejected(t *testing.T) {
	acct := mustEnv(t, "CF_ACCOUNT_ID")
	token := mustEnv(t, "CF_API_TOKEN")
	tunnel := mustEnv(t, "CF_TUNNEL_ID")
	host := testHost(t)

	client := cloudflare.New(acct, token)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	first, err := client.CreateHostnameRoute(ctx, host, tunnel, "managed-by=external-dns/integration-test")
	if err != nil {
		t.Fatalf("create %q: %v", host, err)
	}
	t.Cleanup(func() { _ = client.DeleteHostnameRoute(context.Background(), first.ID) })

	// Same hostname, same tunnel.
	_, err = client.CreateHostnameRoute(ctx, host, tunnel, "managed-by=external-dns/duplicate-attempt")
	if err == nil {
		t.Fatal("Cloudflare accepted a duplicate hostname route; adoption's premise no longer holds")
	}
	if !cloudflare.HasCode(err, cloudflare.ErrCodeHostnameAlreadyRouted) {
		t.Errorf("duplicate create error should carry code %d, got: %v", cloudflare.ErrCodeHostnameAlreadyRouted, err)
	}

	// And no second route was created.
	routes, err := client.ListHostnameRoutes(ctx, tunnel)
	if err != nil {
		t.Fatalf("list after duplicate attempt: %v", err)
	}
	n := 0
	for _, r := range routes {
		if r.Hostname == host && r.DeletedAt == nil {
			n++
		}
	}
	if n != 1 {
		t.Errorf("want exactly 1 live route for %q, got %d", host, n)
	}
}
