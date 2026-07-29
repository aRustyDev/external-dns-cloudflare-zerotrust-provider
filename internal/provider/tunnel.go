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

package provider

import (
	"fmt"
	"sort"
	"strings"
)

// tunnelTargetSuffix is appended to a tunnel ID to form its canonical CNAME target.
const tunnelTargetSuffix = ".cfargotunnel.com"

// tunnelResolver maps a hostname to the Cloudflare Tunnel that should carry it.
//
// Single-tunnel mode: fallback is set and entries is empty, so every hostname resolves
// to the one tunnel. Multi-tunnel mode: entries hold domain->tunnel bindings and a
// hostname resolves to the entry with the longest matching domain suffix (most specific
// wins), e.g. "a.apps.private" prefers "apps.private" over "private".
type tunnelResolver struct {
	entries  []tunnelEntry // sorted longest-domain-first
	fallback string        // single-tunnel id; "" when a map is configured
}

type tunnelEntry struct {
	domain   string
	tunnelID string
}

// newSingleTunnelResolver builds a resolver that sends every hostname to one tunnel.
func newSingleTunnelResolver(tunnelID string) *tunnelResolver {
	return &tunnelResolver{fallback: tunnelID}
}

// newMapTunnelResolver builds a resolver from a domain->tunnelID map. Domains are matched
// by longest suffix, so more specific domains take precedence regardless of map order.
func newMapTunnelResolver(m map[string]string) (*tunnelResolver, error) {
	if len(m) == 0 {
		return nil, fmt.Errorf("tunnel map is empty")
	}
	entries := make([]tunnelEntry, 0, len(m))
	for domain, tid := range m {
		d := strings.TrimSpace(strings.TrimPrefix(strings.ToLower(domain), "."))
		if d == "" {
			return nil, fmt.Errorf("tunnel map has an empty domain key")
		}
		if strings.TrimSpace(tid) == "" {
			return nil, fmt.Errorf("tunnel map domain %q has an empty tunnel id", domain)
		}
		entries = append(entries, tunnelEntry{domain: d, tunnelID: strings.TrimSpace(tid)})
	}
	// Longest domain first; tie-break lexically for deterministic ordering.
	sort.Slice(entries, func(i, j int) bool {
		if len(entries[i].domain) != len(entries[j].domain) {
			return len(entries[i].domain) > len(entries[j].domain)
		}
		return entries[i].domain < entries[j].domain
	})
	return &tunnelResolver{entries: entries}, nil
}

// resolve returns the tunnel ID that should carry hostname, and whether one matched.
func (r *tunnelResolver) resolve(hostname string) (string, bool) {
	if r.fallback != "" {
		return r.fallback, true
	}
	h := strings.ToLower(strings.TrimSuffix(hostname, "."))
	for _, e := range r.entries {
		if h == e.domain || strings.HasSuffix(h, "."+e.domain) {
			return e.tunnelID, true
		}
	}
	return "", false
}

// target returns the canonical CNAME target for a tunnel ID.
func (r *tunnelResolver) target(tunnelID string) string {
	return tunnelID + tunnelTargetSuffix
}

// targetFor returns the CNAME target for the tunnel that should carry hostname.
func (r *tunnelResolver) targetFor(hostname string) (string, bool) {
	tid, ok := r.resolve(hostname)
	if !ok {
		return "", false
	}
	return r.target(tid), true
}

// tunnels returns the distinct tunnel IDs this resolver manages.
func (r *tunnelResolver) tunnels() []string {
	if r.fallback != "" {
		return []string{r.fallback}
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(r.entries))
	for _, e := range r.entries {
		if _, dup := seen[e.tunnelID]; dup {
			continue
		}
		seen[e.tunnelID] = struct{}{}
		out = append(out, e.tunnelID)
	}
	return out
}
