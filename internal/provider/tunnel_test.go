package provider

import (
	"sort"
	"testing"
)

func TestResolver_SingleTunnelMatchesEverything(t *testing.T) {
	r := newSingleTunnelResolver("tun-1")
	for _, host := range []string{"a.woven", "b.apps.woven", "anything.example.com"} {
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
		"woven":      "t-root",
		"apps.woven": "t-apps",
	})
	if err != nil {
		t.Fatalf("newMapTunnelResolver: %v", err)
	}
	cases := map[string]string{
		"svc.apps.woven": "t-apps", // most specific
		"apps.woven":     "t-apps", // exact
		"other.woven":    "t-root",
		"woven":          "t-root",
	}
	for host, want := range cases {
		tid, ok := r.resolve(host)
		if !ok || tid != want {
			t.Errorf("resolve(%q) = %q,%v; want %q,true", host, tid, ok, want)
		}
	}
}

func TestResolver_NoMatchReturnsFalse(t *testing.T) {
	r, err := newMapTunnelResolver(map[string]string{"woven": "t-root"})
	if err != nil {
		t.Fatalf("newMapTunnelResolver: %v", err)
	}
	if _, ok := r.resolve("nope.example.com"); ok {
		t.Fatal("resolve of an unmatched domain should return ok=false")
	}
}

func TestResolver_TunnelsDedup(t *testing.T) {
	r, err := newMapTunnelResolver(map[string]string{
		"a.woven": "shared",
		"b.woven": "shared",
		"c.woven": "other",
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
	if _, err := newMapTunnelResolver(map[string]string{"woven": ""}); err == nil {
		t.Error("empty tunnel id should error")
	}
	if _, err := newMapTunnelResolver(map[string]string{"": "t"}); err == nil {
		t.Error("empty domain key should error")
	}
}
