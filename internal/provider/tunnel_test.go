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
	"sort"
	"testing"
)

func TestResolver_SingleTunnelMatchesEverything(t *testing.T) {
	r := newSingleTunnelResolver("tun-1")
	for _, host := range []string{"a.private", "b.apps.private", "anything.example.com"} {
		tid, ok := r.resolve(host)
		if !ok || tid != "tun-1" {
			t.Fatalf("resolve(%q) = %q,%v; want tun-1,true", host, tid, ok)
		}
	}
	if got := r.tunnels(); len(got) != 1 || got[0] != "tun-1" {
		t.Fatalf("tunnels() = %v, want [tun-1]", got)
	}
}

func TestResolver_LongestSuffixWins(t *testing.T) {
	r, err := newMapTunnelResolver(map[string]string{
		"private":      "t-root",
		"apps.private": "t-apps",
	})
	if err != nil {
		t.Fatalf("newMapTunnelResolver: %v", err)
	}
	cases := map[string]string{
		"svc.apps.private": "t-apps", // most specific
		"apps.private":     "t-apps", // exact
		"other.private":    "t-root",
		"private":          "t-root",
	}
	for host, want := range cases {
		tid, ok := r.resolve(host)
		if !ok || tid != want {
			t.Errorf("resolve(%q) = %q,%v; want %q,true", host, tid, ok, want)
		}
	}
}

func TestResolver_NoMatchReturnsFalse(t *testing.T) {
	r, err := newMapTunnelResolver(map[string]string{"private": "t-root"})
	if err != nil {
		t.Fatalf("newMapTunnelResolver: %v", err)
	}
	if _, ok := r.resolve("nope.example.com"); ok {
		t.Fatal("resolve of an unmatched domain should return ok=false")
	}
}

func TestResolver_TunnelsDedup(t *testing.T) {
	r, err := newMapTunnelResolver(map[string]string{
		"a.private": "shared",
		"b.private": "shared",
		"c.private": "other",
	})
	if err != nil {
		t.Fatalf("newMapTunnelResolver: %v", err)
	}
	got := r.tunnels()
	sort.Strings(got)
	if len(got) != 2 || got[0] != "other" || got[1] != "shared" {
		t.Fatalf("tunnels() = %v, want distinct [other shared]", got)
	}
}

func TestResolver_MapValidation(t *testing.T) {
	if _, err := newMapTunnelResolver(map[string]string{}); err == nil {
		t.Error("empty map should error")
	}
	if _, err := newMapTunnelResolver(map[string]string{"private": ""}); err == nil {
		t.Error("empty tunnel id should error")
	}
	if _, err := newMapTunnelResolver(map[string]string{"": "t"}); err == nil {
		t.Error("empty domain key should error")
	}
}
