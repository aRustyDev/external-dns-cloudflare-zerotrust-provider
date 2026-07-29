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
)

// TestLiveOwnershipStrictProtectsForeignRoutes proves against the REAL Cloudflare API that
// ownership-strict mode hides routes this provider does not own — the safety property that lets
// the provider coexist with Terraform as the declared sole owner of some routes.
//
// It is strictly READ-ONLY (List calls only): it creates and deletes nothing, so it is safe to
// run against an account holding production routes and needs only a read-scoped API token.
//
// The assertion is differential, which is what makes it meaningful: the same foreign route must
// be ABSENT with OwnershipStrict=true and PRESENT with OwnershipStrict=false. A test that only
// checked absence would also pass if the domain filter — or a broken List — hid everything.
func TestLiveOwnershipStrictProtectsForeignRoutes(t *testing.T) {
	acct := mustEnv(t, "CF_ACCOUNT_ID")
	token := mustEnv(t, "CF_API_TOKEN")
	tunnel := mustEnv(t, "CF_TUNNEL_ID")
	filter := testDomainFilter(t)

	client := cloudflare.New(acct, token)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	live, err := client.ListHostnameRoutes(ctx, tunnel)
	if err != nil {
		t.Fatalf("list routes on tunnel %s: %v", tunnel, err)
	}

	// Foreign = live, in-filter, and not carrying our owner tag. These are exactly the routes
	// ownership-strict exists to protect.
	strict := newProvider(t, client, tunnel, filter, true)
	relaxed := newProvider(t, client, tunnel, filter, false)

	strictEps, err := strict.Records(ctx)
	if err != nil {
		t.Fatalf("Records (strict): %v", err)
	}
	relaxedEps, err := relaxed.Records(ctx)
	if err != nil {
		t.Fatalf("Records (relaxed): %v", err)
	}

	var foreign []string
	for _, r := range live {
		if r.DeletedAt == nil && hasEndpoint(relaxedEps, r.Hostname) {
			foreign = append(foreign, r.Hostname)
		}
	}
	if len(foreign) == 0 {
		t.Skipf("no live in-filter (%q) routes on tunnel %s; nothing to protect — "+
			"pre-create one foreign route to exercise this test", filter, tunnel)
	}
	t.Logf("live in-filter routes visible without ownership-strict: %v", foreign)

	for _, host := range foreign {
		if hasEndpoint(strictEps, host) {
			t.Errorf("ownership-strict LEAKED foreign route %q: it must not be managed "+
				"(and therefore must never be deletable) by this provider", host)
		}
	}
	if len(strictEps) != 0 {
		t.Errorf("ownership-strict returned %d record(s) but this owner created none: %v",
			len(strictEps), endpointNames(strictEps))
	}
}

func endpointNames(eps []*endpoint.Endpoint) []string {
	out := make([]string, 0, len(eps))
	for _, e := range eps {
		out = append(out, e.DNSName)
	}
	return out
}

func newProvider(t *testing.T, client *cloudflare.Client, tunnel, filter string, strict bool) *cfprovider.Provider {
	t.Helper()
	p, err := cfprovider.New(cfprovider.Config{
		Client:          client,
		TunnelID:        tunnel,
		OwnerID:         "integration-test",
		OwnershipStrict: strict,
		DomainFilter:    []string{filter},
	})
	if err != nil {
		t.Fatalf("New provider (strict=%v): %v", strict, err)
	}
	return p
}
