package cloudflare

import (
	"context"
	"encoding/json"
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
		_, _ = w.Write([]byte(`{"success":true,"errors":[],"result":{"id":"route-1","hostname":"foo.woven","tunnel_id":"tun-1"}}`))
	}))
	defer srv.Close()

	c := New(acct, "tok-xyz", WithBaseURL(srv.URL))
	route, err := c.CreateHostnameRoute(context.Background(), "foo.woven", "tun-1", "managed-by=external-dns")
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
	if gotBody.Hostname != "foo.woven" || gotBody.TunnelID != "tun-1" {
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
			_, _ = w.Write([]byte(`{"success":true,"result":[{"id":"1","hostname":"a.woven","tunnel_id":"t"}],"result_info":{"page":1,"per_page":1,"total_count":2}}`))
		default:
			_, _ = w.Write([]byte(`{"success":true,"result":[{"id":"2","hostname":"b.woven","tunnel_id":"t"}],"result_info":{"page":2,"per_page":1,"total_count":2}}`))
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

func TestAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":10000,"message":"Authentication error"}]}`))
	}))
	defer srv.Close()

	c := New(acct, "bad", WithBaseURL(srv.URL))
	_, err := c.CreateHostnameRoute(context.Background(), "x.woven", "t", "")
	if err == nil || !strings.Contains(err.Error(), "Authentication error") {
		t.Fatalf("want auth error surfaced, got %v", err)
	}
}
