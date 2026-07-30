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

package main

import (
	"io"
	"log/slog"
	"testing"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// An unset COREDNS_CONFIGMAP must yield a genuinely nil interface. A typed nil would make the
// provider believe leg 2 is enabled and panic on the first reconcile, so this asserts the
// interface itself is nil rather than merely that no error was returned.
func TestBuildFragment_DisabledYieldsUntypedNil(t *testing.T) {
	for _, spec := range []string{"", "   "} {
		got, err := buildFragment(quietLogger(), spec)
		if err != nil {
			t.Fatalf("buildFragment(%q): %v", spec, err)
		}
		if got != nil {
			t.Errorf("buildFragment(%q) returned a non-nil interface (%T); leg 2 would be "+
				"treated as enabled and panic", spec, got)
		}
	}
}

func TestBuildFragment_RejectsMalformedSpec(t *testing.T) {
	for _, spec := range []string{"no-slash", "/name", "namespace/", "/"} {
		if _, err := buildFragment(quietLogger(), spec); err == nil {
			t.Errorf("buildFragment(%q) should have failed", spec)
		}
	}
}

func TestParseTunnelMap(t *testing.T) {
	got, err := parseTunnelMap("a.woven=t1, b.woven = t2 ")
	if err != nil {
		t.Fatalf("parseTunnelMap: %v", err)
	}
	if got["a.woven"] != "t1" || got["b.woven"] != "t2" {
		t.Errorf("parsed = %v", got)
	}
	if m, err := parseTunnelMap(""); err != nil || m != nil {
		t.Errorf("empty input should be (nil, nil), got (%v, %v)", m, err)
	}
	for _, bad := range []string{"noequals", "=t1", "domain="} {
		if _, err := parseTunnelMap(bad); err == nil {
			t.Errorf("parseTunnelMap(%q) should have failed", bad)
		}
	}
}

func TestEnvBoolDefaults(t *testing.T) {
	if !envBool("CFZT_TEST_UNSET_VAR", true) {
		t.Error("unset var should return the default")
	}
	if envBool("CFZT_TEST_UNSET_VAR", false) {
		t.Error("unset var should return the default")
	}
	t.Setenv("CFZT_TEST_SET_VAR", "yes")
	if !envBool("CFZT_TEST_SET_VAR", false) {
		t.Error(`"yes" should parse as true`)
	}
	t.Setenv("CFZT_TEST_SET_VAR", "nope")
	if envBool("CFZT_TEST_SET_VAR", true) {
		t.Error(`anything unrecognised should be false, not the default`)
	}
}
