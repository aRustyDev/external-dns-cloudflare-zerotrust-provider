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
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arustydev/external-dns-cloudflare-zerotrust-provider/internal/cloudflare"
)

const pruneAcct = "acct-1"

// fakeCloudflare serves just enough of the hostname-routes API for prune: list (with the tunnel_id
// filter) and delete by id. It records what was asked of it.
type fakeCloudflare struct {
	mu          sync.Mutex
	routes      []cloudflare.HostnameRoute
	deleted     []string
	listQueries []string // the tunnel_id query value of each list call
	failDelete  map[string]bool
	failList    bool
}

func (f *fakeCloudflare) handler() http.Handler {
	base := "/accounts/" + pruneAcct + "/zerotrust/routes/hostname"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		fail := func() {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":1000,"message":"boom"}]}`))
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == base:
			tunnel := r.URL.Query().Get("tunnel_id")
			f.listQueries = append(f.listQueries, tunnel)
			if f.failList {
				fail()
				return
			}
			out := []cloudflare.HostnameRoute{}
			for _, rt := range f.routes {
				if tunnel == "" || rt.TunnelID == tunnel {
					out = append(out, rt)
				}
			}
			body, _ := json.Marshal(map[string]any{
				"success": true, "result": out,
				"result_info": map[string]int{"page": 1, "per_page": 100, "count": len(out), "total_count": len(out)},
			})
			_, _ = w.Write(body)
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, base+"/"):
			id := strings.TrimPrefix(r.URL.Path, base+"/")
			if f.failDelete[id] {
				fail()
				return
			}
			f.deleted = append(f.deleted, id)
			_, _ = w.Write([]byte(`{"success":true,"result":{"id":"` + id + `"}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

// run drives runPrune against a fake and returns the exit code and what it printed.
func (f *fakeCloudflare) run(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	var out, errOut bytes.Buffer
	code = runPrune(args, pruneDeps{
		getenv: func(k string) string {
			return map[string]string{"CF_ACCOUNT_ID": pruneAcct, "CF_API_TOKEN": "tok"}[k]
		},
		newClient: func(accountID, apiToken string) pruneClient {
			return cloudflare.New(accountID, apiToken, cloudflare.WithBaseURL(srv.URL))
		},
		stdout: &out,
		stderr: &errOut,
	})
	return code, out.String(), errOut.String()
}

func tagged(owner string) string { return "managed-by=external-dns/" + owner }

func sampleRoutes() []cloudflare.HostnameRoute {
	return []cloudflare.HostnameRoute{
		{ID: "x1", Hostname: "a.edns.woven", TunnelID: "tun-a", Comment: tagged("x")},
		{ID: "x2", Hostname: "b.apps.woven", TunnelID: "tun-b", Comment: tagged("x")},
		{ID: "y1", Hostname: "c.edns.woven", TunnelID: "tun-a", Comment: tagged("y")},
		{ID: "u1", Hostname: "d.edns.woven", TunnelID: "tun-a", Comment: "hand-created"},
		{ID: "u2", Hostname: "e.edns.woven", TunnelID: "tun-a"},
	}
}

// The default is to look, not touch.
func TestPrune_DryRunListsAndDeletesNothing(t *testing.T) {
	f := &fakeCloudflare{routes: sampleRoutes()}
	code, out, _ := f.run(t, "--owner", "x")

	if code != pruneOK {
		t.Fatalf("exit = %d, want 0", code)
	}
	if len(f.deleted) != 0 {
		t.Fatalf("a dry run deleted %v", f.deleted)
	}
	for _, want := range []string{"a.edns.woven", "b.apps.woven", "x1", "x2", "Dry run", "--apply"} {
		if !strings.Contains(out, want) {
			t.Errorf("output should mention %q; got:\n%s", want, out)
		}
	}
	for _, unwanted := range []string{"c.edns.woven", "d.edns.woven", "e.edns.woven"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("output lists %q, which does not belong to owner x:\n%s", unwanted, out)
		}
	}
}

// --apply deletes exactly the owner's routes: never another owner's, never an untagged one.
func TestPrune_ApplyDeletesOnlyTheOwnersRoutes(t *testing.T) {
	f := &fakeCloudflare{routes: sampleRoutes()}
	code, out, _ := f.run(t, "--owner", "x", "--apply")

	if code != pruneOK {
		t.Fatalf("exit = %d, want 0\n%s", code, out)
	}
	if len(f.deleted) != 2 || f.deleted[0] != "x1" || f.deleted[1] != "x2" {
		t.Fatalf("deleted = %v, want exactly [x1 x2]", f.deleted)
	}
	if !strings.Contains(out, "Deleted 2 of 2") {
		t.Errorf("summary missing; got:\n%s", out)
	}
}

// A near-miss owner id must not match: x is not xy, and not a prefix of x-prod.
func TestPrune_OwnerMatchIsExact(t *testing.T) {
	f := &fakeCloudflare{routes: []cloudflare.HostnameRoute{
		{ID: "1", Hostname: "a.woven", Comment: tagged("x-prod")},
		{ID: "2", Hostname: "b.woven", Comment: tagged("xy")},
		{ID: "3", Hostname: "c.woven", Comment: tagged("x")},
	}}
	if code, _, _ := f.run(t, "--owner", "x", "--apply"); code != pruneOK {
		t.Fatalf("exit = %d, want 0", code)
	}
	if len(f.deleted) != 1 || f.deleted[0] != "3" {
		t.Fatalf("deleted = %v, want only [3]", f.deleted)
	}
}

// --tunnel limits which tunnels are listed at all, and may be repeated or comma-separated.
func TestPrune_TunnelFlagScopesTheList(t *testing.T) {
	t.Run("one tunnel", func(t *testing.T) {
		f := &fakeCloudflare{routes: sampleRoutes()}
		if code, _, _ := f.run(t, "--owner", "x", "--tunnel", "tun-a", "--apply"); code != pruneOK {
			t.Fatalf("exit = %d", code)
		}
		if len(f.listQueries) != 1 || f.listQueries[0] != "tun-a" {
			t.Errorf("list queries = %v, want only tun-a", f.listQueries)
		}
		if len(f.deleted) != 1 || f.deleted[0] != "x1" {
			t.Errorf("deleted = %v, want only [x1] (x2 is on another tunnel)", f.deleted)
		}
	})
	t.Run("repeated and comma-separated", func(t *testing.T) {
		f := &fakeCloudflare{routes: sampleRoutes()}
		if code, _, _ := f.run(t, "--owner", "x", "--tunnel", "tun-a", "--tunnel", "tun-b,tun-c", "--apply"); code != pruneOK {
			t.Fatalf("exit = %d", code)
		}
		if got := strings.Join(f.listQueries, ","); got != "tun-a,tun-b,tun-c" {
			t.Errorf("list queries = %q, want tun-a,tun-b,tun-c", got)
		}
		if len(f.deleted) != 2 {
			t.Errorf("deleted = %v, want both of x's routes", f.deleted)
		}
	})
	t.Run("none lists the whole account", func(t *testing.T) {
		f := &fakeCloudflare{routes: sampleRoutes()}
		f.run(t, "--owner", "x")
		if len(f.listQueries) != 1 || f.listQueries[0] != "" {
			t.Errorf("list queries = %q, want one account-wide list", f.listQueries)
		}
	})
}

func TestPrune_DomainFilterNarrows(t *testing.T) {
	f := &fakeCloudflare{routes: sampleRoutes()}
	if code, _, _ := f.run(t, "--owner", "x", "--domain-filter", "apps.woven", "--apply"); code != pruneOK {
		t.Fatalf("exit = %d", code)
	}
	if len(f.deleted) != 1 || f.deleted[0] != "x2" {
		t.Fatalf("deleted = %v, want only [x2] (the one under apps.woven)", f.deleted)
	}
}

// A soft-deleted route is already gone from Cloudflare's point of view.
func TestPrune_SkipsSoftDeletedRoutes(t *testing.T) {
	gone := time.Now()
	f := &fakeCloudflare{routes: []cloudflare.HostnameRoute{
		{ID: "live", Hostname: "a.woven", Comment: tagged("x")},
		{ID: "dead", Hostname: "b.woven", Comment: tagged("x"), DeletedAt: &gone},
	}}
	f.run(t, "--owner", "x", "--apply")
	if len(f.deleted) != 1 || f.deleted[0] != "live" {
		t.Fatalf("deleted = %v, want only [live]", f.deleted)
	}
}

// One failed delete must not stop the rest, and must be reflected in the exit code.
func TestPrune_DeleteFailureExitsNonZeroButContinues(t *testing.T) {
	f := &fakeCloudflare{routes: sampleRoutes(), failDelete: map[string]bool{"x1": true}}
	code, out, errOut := f.run(t, "--owner", "x", "--apply")

	if code != pruneFailed {
		t.Fatalf("exit = %d, want 1", code)
	}
	if len(f.deleted) != 1 || f.deleted[0] != "x2" {
		t.Errorf("deleted = %v, want the other route still deleted", f.deleted)
	}
	if !strings.Contains(errOut, "FAILED") || !strings.Contains(errOut, "x1") {
		t.Errorf("the failure should be reported; stderr:\n%s", errOut)
	}
	if !strings.Contains(out, "Deleted 1 of 2") {
		t.Errorf("summary should say 1 of 2; got:\n%s", out)
	}
}

// If the list itself fails there is nothing safe to delete.
func TestPrune_ListFailureDeletesNothing(t *testing.T) {
	f := &fakeCloudflare{routes: sampleRoutes(), failList: true}
	code, _, errOut := f.run(t, "--owner", "x", "--apply")
	if code != pruneFailed {
		t.Fatalf("exit = %d, want 1", code)
	}
	if len(f.deleted) != 0 {
		t.Errorf("deleted %v after a failed list", f.deleted)
	}
	if !strings.Contains(errOut, "list routes") {
		t.Errorf("stderr should explain; got:\n%s", errOut)
	}
}

func TestPrune_NothingToPrune(t *testing.T) {
	f := &fakeCloudflare{routes: sampleRoutes()}
	code, out, _ := f.run(t, "--owner", "nobody", "--apply")
	if code != pruneOK {
		t.Fatalf("exit = %d, want 0", code)
	}
	if !strings.Contains(out, "Nothing to prune") {
		t.Errorf("output = %q, want 'Nothing to prune'", out)
	}
	if len(f.deleted) != 0 {
		t.Errorf("deleted %v for an owner with no routes", f.deleted)
	}
}

func TestPrune_UsageErrors(t *testing.T) {
	cases := map[string][]string{
		"missing owner":       {},
		"blank owner":         {"--owner", "  "},
		"unexpected argument": {"--owner", "x", "stray"},
		"unknown flag":        {"--owner", "x", "--nope"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			f := &fakeCloudflare{routes: sampleRoutes()}
			code, _, errOut := f.run(t, args...)
			if code != pruneUsageError {
				t.Errorf("exit = %d, want 2; stderr:\n%s", code, errOut)
			}
			if len(f.deleted) != 0 || len(f.listQueries) != 0 {
				t.Error("a usage error must not touch Cloudflare")
			}
		})
	}
}

func TestPrune_MissingCredentialsIsAUsageError(t *testing.T) {
	var out, errOut bytes.Buffer
	code := runPrune([]string{"--owner", "x"}, pruneDeps{
		getenv:    func(string) string { return "" },
		newClient: func(string, string) pruneClient { t.Fatal("must not build a client without credentials"); return nil },
		stdout:    &out, stderr: &errOut,
	})
	if code != pruneUsageError {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(errOut.String(), "CF_ACCOUNT_ID") {
		t.Errorf("stderr should name the missing variables; got:\n%s", errOut.String())
	}
}

func TestPrune_HelpExitsZero(t *testing.T) {
	f := &fakeCloudflare{}
	code, _, errOut := f.run(t, "-h")
	if code != pruneOK {
		t.Fatalf("exit = %d, want 0", code)
	}
	if !strings.Contains(errOut, "Only run it for an owner whose instance is no longer running") {
		t.Errorf("help should carry the safety warning; got:\n%s", errOut)
	}
}
