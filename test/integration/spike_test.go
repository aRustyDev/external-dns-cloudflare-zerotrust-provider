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

// Spike tests for the open questions behind the multi-tunnel design. Like the scoped-token test,
// each one MEASURES and logs "OBSERVED ..." lines instead of asserting the API behaves a certain
// way; only a broken fixture fails a test. The answers go in docs/multi-tunnel-lifecycle.md
// section 8. The retarget question is answered by TestLiveRetargetPreservesRouteID.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/arustydev/external-dns-cloudflare-zerotrust-provider/internal/cloudflare"
)

const spikeComment = "managed-by=external-dns/integration-test"

// TestLiveSoftDeleteWindow measures how long a hostname stays refused (1108) after its route is
// deleted. Cloudflare soft-deletes routes, and if a soft-deleted route still holds the name, the
// gap in a handoff is that window PLUS a reconcile interval, not just the interval.
func TestLiveSoftDeleteWindow(t *testing.T) {
	acct := mustEnv(t, "CF_ACCOUNT_ID")
	token := mustEnv(t, "CF_API_TOKEN")
	tunnel := mustEnv(t, "CF_TUNNEL_ID")
	c := cloudflare.New(acct, token)
	host := uniqueHost(t, "softdel")
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	first, err := c.CreateHostnameRoute(ctx, host, tunnel, spikeComment)
	if err != nil {
		t.Fatalf("create %q: %v", host, err)
	}
	cleanupHost(t, c, host, tunnel)
	if err := c.DeleteHostnameRoute(ctx, first.ID); err != nil {
		t.Fatalf("delete %q: %v", host, err)
	}

	start := time.Now()
	for {
		again, err := c.CreateHostnameRoute(ctx, host, tunnel, spikeComment)
		if err == nil {
			t.Logf("OBSERVED soft-delete window: the hostname was re-creatable after %s (new id %s, first id %s)",
				time.Since(start).Round(time.Millisecond), again.ID, first.ID)
			return
		}
		if !cloudflare.HasCode(err, cloudflare.ErrCodeHostnameAlreadyRouted) {
			t.Fatalf("re-create failed with something other than 1108: %v", err)
		}
		if time.Since(start) > 60*time.Second {
			t.Logf("OBSERVED soft-delete window: still refused with 1108 after 60s")
			return
		}
		time.Sleep(2 * time.Second)
	}
}

// TestLiveWildcardVsExact records how a wildcard route and an exact route for the same suffix
// interact in the API: how the wildcard is stored, and whether an exact create on ANOTHER tunnel is
// refused. Which of the two wins when a client resolves the name needs a WARP client and cannot be
// observed here.
func TestLiveWildcardVsExact(t *testing.T) {
	c, tunnelA, tunnelB := twoTunnelEnv(t)
	base := uniqueHost(t, "wild")
	wildcard, exact := "*."+base, "a."+base
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	wc, err := c.CreateHostnameRoute(ctx, wildcard, tunnelA, spikeComment)
	observe(t, "create of a wildcard hostname on tunnel A", err)
	if err != nil {
		return
	}
	cleanupHost(t, c, wc.Hostname, tunnelA, tunnelB)
	t.Logf("OBSERVED a wildcard create for %q is stored as hostname=%q", wildcard, wc.Hostname)

	ex, err := c.CreateHostnameRoute(ctx, exact, tunnelB, spikeComment)
	observe(t, "create of an exact hostname under that wildcard, on tunnel B", err)
	if err == nil {
		cleanupHost(t, c, ex.Hostname, tunnelA, tunnelB)
	}
}

// TestLiveTunnelDeleteCascade records what happens to a tunnel's hostname routes when the tunnel is
// deleted: removed with it, left behind pointing at a dead tunnel, or the delete refused. It
// DELETES the tunnel named in CF_TUNNEL_ID_DISPOSABLE, so that must be a tunnel you do not need.
func TestLiveTunnelDeleteCascade(t *testing.T) {
	acct := mustEnv(t, "CF_ACCOUNT_ID")
	token := mustEnv(t, "CF_API_TOKEN")
	disposable := mustEnv(t, "CF_TUNNEL_ID_DISPOSABLE")
	for _, key := range []string{"CF_TUNNEL_ID", "CF_TUNNEL_ID_B"} {
		if os.Getenv(key) == disposable {
			t.Skipf("CF_TUNNEL_ID_DISPOSABLE equals %s; refusing to delete a tunnel the other tests use", key)
		}
	}
	c := cloudflare.New(acct, token)
	host := uniqueHost(t, "cascade")
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	created, err := c.CreateHostnameRoute(ctx, host, disposable, spikeComment)
	if err != nil {
		t.Fatalf("create %q on the disposable tunnel: %v", host, err)
	}
	t.Cleanup(func() { _ = c.DeleteHostnameRoute(context.Background(), created.ID) })

	status, body, err := rawCall(ctx, token, http.MethodDelete, "/accounts/"+acct+"/cfd_tunnel/"+disposable, nil, "")
	if err != nil {
		t.Fatalf("delete the disposable tunnel: %v", err)
	}
	t.Logf("OBSERVED tunnel delete: status=%d body=%s", status, clip(body, 300))

	routes, err := c.ListHostnameRoutes(ctx, "")
	if err != nil {
		t.Fatalf("list after the tunnel delete: %v", err)
	}
	for _, r := range routes {
		if r.ID == created.ID {
			t.Logf("OBSERVED after the tunnel delete the route still exists: tunnel_id=%s deleted_at=%v", r.TunnelID, r.DeletedAt)
			return
		}
	}
	t.Logf("OBSERVED after the tunnel delete the route is gone from the account-wide list")
}

// TestLiveListFiltersAndCommentLimit records whether the list endpoint filters by hostname and by
// comment, and how long a comment the API accepts.
func TestLiveListFiltersAndCommentLimit(t *testing.T) {
	acct := mustEnv(t, "CF_ACCOUNT_ID")
	token := mustEnv(t, "CF_API_TOKEN")
	tunnel := mustEnv(t, "CF_TUNNEL_ID")
	c := cloudflare.New(acct, token)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	hostX, hostY := uniqueHost(t, "filter-x"), uniqueHost(t, "filter-y")
	commentX, commentY := spikeComment+"/filter-x", spikeComment+"/filter-y"
	for host, comment := range map[string]string{hostX: commentX, hostY: commentY} {
		if _, err := c.CreateHostnameRoute(ctx, host, tunnel, comment); err != nil {
			t.Fatalf("fixture: create %q: %v", host, err)
		}
		cleanupHost(t, c, host, tunnel)
	}

	path := "/accounts/" + acct + "/zerotrust/routes/hostname"
	for _, q := range []struct{ param, value, wantPresent, wantAbsent string }{
		{"hostname", hostX, hostX, hostY},
		{"comment", commentX, hostX, hostY},
	} {
		status, body, err := rawCall(ctx, token, http.MethodGet, path, url.Values{q.param: {q.value}, "tunnel_id": {tunnel}}, "")
		if err != nil {
			t.Fatalf("list with %s=: %v", q.param, err)
		}
		var env struct {
			Result []cloudflare.HostnameRoute `json:"result"`
		}
		if err := json.Unmarshal(body, &env); err != nil || status != http.StatusOK {
			t.Logf("OBSERVED list filter %s=: status=%d body=%s", q.param, status, clip(body, 300))
			continue
		}
		present, absent := activeHost(env.Result, q.wantPresent), activeHost(env.Result, q.wantAbsent)
		verdict := "works"
		if absent {
			verdict = "is IGNORED"
		}
		t.Logf("OBSERVED list filter %s=: status=%d, %d routes returned; has the matching route: %v; "+
			"still has the non-matching one: %v (so the filter %s)", q.param, status, len(env.Result),
			present, absent, verdict)
	}

	// How long a comment is accepted? Try increasing lengths and stop at the first refusal.
	for _, n := range []int{100, 255, 500, 1000, 2000, 5000} {
		host := uniqueHost(t, "comment")
		_, err := c.CreateHostnameRoute(ctx, host, tunnel, strings.Repeat("c", n))
		observe(t, "create with a comment of "+strconv.Itoa(n)+" characters", err)
		if err != nil {
			return
		}
		cleanupHost(t, c, host, tunnel)
	}
	t.Logf("OBSERVED comment limit: every length up to 5000 characters was accepted")
}
