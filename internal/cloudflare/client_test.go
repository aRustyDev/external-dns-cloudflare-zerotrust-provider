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

package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const acct = "abc123account"

func TestCreateHostnameRoute(t *testing.T) {
	var gotBody createRequest
	var gotAuth, gotMethod, gotPath string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotMethod = r.Method
		gotPath = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"errors":[],"result":{"id":"route-1","hostname":"foo.private","tunnel_id":"tun-1"}}`))
	}))
	defer srv.Close()

	c := New(acct, "tok-xyz", WithBaseURL(srv.URL))
	route, err := c.CreateHostnameRoute(context.Background(), "foo.private", "tun-1", "managed-by=external-dns")
	if err != nil {
		t.Fatalf("CreateHostnameRoute: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %s, want POST", gotMethod)
	}
	if want := "/accounts/" + acct + "/zerotrust/routes/hostname"; gotPath != want {
		t.Errorf("path = %s, want %s", gotPath, want)
	}
	if gotAuth != "Bearer tok-xyz" {
		t.Errorf("auth = %q, want bearer token", gotAuth)
	}
	if gotBody.Hostname != "foo.private" || gotBody.TunnelID != "tun-1" {
		t.Errorf("body = %+v", gotBody)
	}
	if route.ID != "route-1" {
		t.Errorf("route id = %q", route.ID)
	}
}

func TestListHostnameRoutes_Paginates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page")
		w.Header().Set("Content-Type", "application/json")
		switch page {
		case "1":
			_, _ = w.Write([]byte(`{"success":true,"result":[{"id":"1","hostname":"a.private","tunnel_id":"t"}],"result_info":{"page":1,"per_page":1,"total_count":2}}`))
		default:
			_, _ = w.Write([]byte(`{"success":true,"result":[{"id":"2","hostname":"b.private","tunnel_id":"t"}],"result_info":{"page":2,"per_page":1,"total_count":2}}`))
		}
	}))
	defer srv.Close()

	c := New(acct, "tok", WithBaseURL(srv.URL))
	routes, err := c.ListHostnameRoutes(context.Background(), "t")
	if err != nil {
		t.Fatalf("ListHostnameRoutes: %v", err)
	}
	if len(routes) != 2 {
		t.Fatalf("want 2 routes across pages, got %d", len(routes))
	}
}

func TestDeleteHostnameRoute(t *testing.T) {
	var gotMethod, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		_, _ = w.Write([]byte(`{"success":true,"result":{"id":"route-1","deleted_at":"2026-01-01T00:00:00Z"}}`))
	}))
	defer srv.Close()

	c := New(acct, "tok", WithBaseURL(srv.URL))
	if err := c.DeleteHostnameRoute(context.Background(), "route-1"); err != nil {
		t.Fatalf("DeleteHostnameRoute: %v", err)
	}
	if gotMethod != http.MethodDelete {
		t.Errorf("method = %s, want DELETE", gotMethod)
	}
	if !strings.HasSuffix(gotPath, "/zerotrust/routes/hostname/route-1") {
		t.Errorf("path = %s", gotPath)
	}
}

// PatchHostnameRouteComment must send ONLY the comment. Sending hostname/tunnel_id would work
// against the live API too, but it would make an accidental tunnel retarget expressible — the
// one thing adoption must never do.
func TestPatchHostnameRouteComment_SendsOnlyComment(t *testing.T) {
	var gotMethod, gotPath string
	var gotBody map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
		_, _ = w.Write([]byte(`{"success":true,"result":{"id":"route-1","hostname":"foo.private","tunnel_id":"tun-1","comment":"managed-by=external-dns/x"}}`))
	}))
	defer srv.Close()

	c := New(acct, "tok", WithBaseURL(srv.URL))
	route, err := c.PatchHostnameRouteComment(context.Background(), "route-1", "managed-by=external-dns/x")
	if err != nil {
		t.Fatalf("PatchHostnameRouteComment: %v", err)
	}
	if gotMethod != http.MethodPatch {
		t.Errorf("method = %s, want PATCH", gotMethod)
	}
	if !strings.HasSuffix(gotPath, "/zerotrust/routes/hostname/route-1") {
		t.Errorf("path = %s", gotPath)
	}
	if len(gotBody) != 1 || gotBody["comment"] != "managed-by=external-dns/x" {
		t.Errorf("body = %v, want exactly {comment}", gotBody)
	}
	// Route identity must come back unchanged — this is what makes adoption zero-downtime.
	if route.ID != "route-1" || route.TunnelID != "tun-1" || route.Hostname != "foo.private" {
		t.Errorf("route identity changed: %+v", route)
	}
}

// A duplicate hostname is rejected with 409 / 1108 by the live API. Callers act on the CODE, not
// the message text (whose "another tunnel" wording is wrong for same-tunnel duplicates).
func TestHasCode_DetectsHostnameAlreadyRouted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":1108,"message":"Hostname Route already routed to another tunnel"}]}`))
	}))
	defer srv.Close()

	c := New(acct, "tok", WithBaseURL(srv.URL))
	_, err := c.CreateHostnameRoute(context.Background(), "dup.private", "tun-1", "")
	if err == nil {
		t.Fatal("want an error for a duplicate hostname")
	}
	if !HasCode(err, ErrCodeHostnameAlreadyRouted) {
		t.Errorf("HasCode(err, %d) = false, want true (err = %v)", ErrCodeHostnameAlreadyRouted, err)
	}
	if HasCode(err, 10000) {
		t.Error("HasCode matched a code the response did not carry")
	}
	if HasCode(errors.New("plain error"), ErrCodeHostnameAlreadyRouted) {
		t.Error("HasCode must be false for a non-API error")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusConflict {
		t.Errorf("want an *APIError carrying status 409, got %#v", err)
	}
}

func TestAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":10000,"message":"Authentication error"}]}`))
	}))
	defer srv.Close()

	c := New(acct, "bad", WithBaseURL(srv.URL))
	_, err := c.CreateHostnameRoute(context.Background(), "x.private", "t", "")
	if err == nil || !strings.Contains(err.Error(), "Authentication error") {
		t.Fatalf("want auth error surfaced, got %v", err)
	}
}

// PatchHostnameRoute is the retarget primitive. It sends exactly the fields that are set, so a
// caller can send the documented full body or a single field, and the route it gets back carries
// the new tunnel under the SAME id.
func TestPatchHostnameRoute_SendsOnlySetFields(t *testing.T) {
	var gotMethod, gotPath string
	var gotBody map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		gotBody = nil
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
		_, _ = w.Write([]byte(`{"success":true,"result":{"id":"route-1","hostname":"foo.private","tunnel_id":"tun-2","comment":"managed-by=external-dns/x"}}`))
	}))
	defer srv.Close()
	c := New(acct, "tok", WithBaseURL(srv.URL))

	route, err := c.PatchHostnameRoute(context.Background(), "route-1", RoutePatch{
		Hostname: "foo.private", TunnelID: "tun-2", Comment: "managed-by=external-dns/x",
	})
	if err != nil {
		t.Fatalf("PatchHostnameRoute: %v", err)
	}
	if gotMethod != http.MethodPatch || !strings.HasSuffix(gotPath, "/zerotrust/routes/hostname/route-1") {
		t.Errorf("request = %s %s, want PATCH .../zerotrust/routes/hostname/route-1", gotMethod, gotPath)
	}
	if len(gotBody) != 3 || gotBody["hostname"] != "foo.private" || gotBody["tunnel_id"] != "tun-2" ||
		gotBody["comment"] != "managed-by=external-dns/x" {
		t.Errorf("full body = %v, want {hostname, tunnel_id, comment}", gotBody)
	}
	if route.ID != "route-1" || route.TunnelID != "tun-2" {
		t.Errorf("route = %+v, want the same id on the new tunnel", route)
	}

	// A zero field is omitted rather than sent as an empty string, which could blank the field.
	if _, err := c.PatchHostnameRoute(context.Background(), "route-1", RoutePatch{TunnelID: "tun-2"}); err != nil {
		t.Fatalf("PatchHostnameRoute: %v", err)
	}
	if len(gotBody) != 1 || gotBody["tunnel_id"] != "tun-2" {
		t.Errorf("single-field body = %v, want exactly {tunnel_id}", gotBody)
	}
}

// A client given no token must send no Authorization header, and WithHeader must reach every
// request. Together they let the client authenticate to a broker with Access service-token headers.
func TestClient_NoTokenSendsNoAuthorizationAndWithHeaderIsSent(t *testing.T) {
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		_, _ = w.Write([]byte(`{"success":true,"result":[],"result_info":{"page":1,"per_page":100,"count":0,"total_count":0}}`))
	}))
	defer srv.Close()

	c := New(acct, "", WithBaseURL(srv.URL), WithHeader("X-One", "1"), WithHeader("X-Two", "2"), WithHeader("X-One", "last"))
	if _, err := c.ListHostnameRoutes(context.Background(), ""); err != nil {
		t.Fatalf("ListHostnameRoutes: %v", err)
	}
	if v := got.Get("Authorization"); v != "" {
		t.Errorf("Authorization = %q, want none for an empty token", v)
	}
	if got.Get("X-One") != "last" || got.Get("X-Two") != "2" {
		t.Errorf("headers = %v, want X-One=last (the last value wins) and X-Two=2", got)
	}

	// With a token it still sends the bearer header, as before.
	withToken := New(acct, "tok", WithBaseURL(srv.URL))
	if _, err := withToken.ListHostnameRoutes(context.Background(), ""); err != nil {
		t.Fatalf("ListHostnameRoutes: %v", err)
	}
	if v := got.Get("Authorization"); v != "Bearer tok" {
		t.Errorf("Authorization = %q, want the bearer token", v)
	}
}
