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
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func envOf(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func brokerEnv(extra map[string]string) map[string]string {
	m := map[string]string{
		"ROUTE_BACKEND":        "broker",
		"CF_ACCOUNT_ID":        "acct1",
		"BROKER_URL":           "https://broker.example.workers.dev",
		"BROKER_CLIENT_ID":     "client-x.access",
		"BROKER_CLIENT_SECRET": "very-secret-value",
	}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func TestNewRouteClient_DefaultsToCloudflare(t *testing.T) {
	_, backend, err := newRouteClient(envOf(map[string]string{"CF_ACCOUNT_ID": "acct1", "CF_API_TOKEN": "tok"}))
	if err != nil || backend != backendCloudflare {
		t.Fatalf("backend = %q, err = %v; want the cloudflare backend", backend, err)
	}
}

func TestNewRouteClient_CloudflareNeedsAnAccountAndAToken(t *testing.T) {
	for name, env := range map[string]map[string]string{
		"no account": {"CF_API_TOKEN": "tok"},
		"no token":   {"CF_ACCOUNT_ID": "acct1"},
	} {
		if _, _, err := newRouteClient(envOf(env)); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

func TestNewRouteClient_RejectsAnUnknownBackend(t *testing.T) {
	_, _, err := newRouteClient(envOf(map[string]string{"ROUTE_BACKEND": "carrier-pigeon", "CF_ACCOUNT_ID": "a"}))
	if err == nil || !strings.Contains(err.Error(), "carrier-pigeon") {
		t.Fatalf("want an error naming the bad value; got %v", err)
	}
}

func TestNewRouteClient_BrokerNeedsItsSettings(t *testing.T) {
	for _, missing := range []string{"BROKER_URL", "BROKER_CLIENT_ID", "BROKER_CLIENT_SECRET", "CF_ACCOUNT_ID"} {
		t.Run(missing, func(t *testing.T) {
			env := brokerEnv(nil)
			delete(env, missing)
			_, _, err := newRouteClient(envOf(env))
			if err == nil || !strings.Contains(err.Error(), missing) {
				t.Fatalf("want an error naming %s; got %v", missing, err)
			}
		})
	}
}

func TestNewRouteClient_BrokerBackendIsCaseAndSpaceInsensitive(t *testing.T) {
	_, backend, err := newRouteClient(envOf(brokerEnv(map[string]string{"ROUTE_BACKEND": "  Broker "})))
	if err != nil || backend != backendBroker {
		t.Fatalf("backend = %q, err = %v", backend, err)
	}
}

// The reason the broker backend exists is that no account-wide token reaches the cluster. Running
// with both set would keep the exposure while appearing to have removed it, so it must not start.
func TestNewRouteClient_BrokerRefusesToRunBesideAnAccountToken(t *testing.T) {
	_, _, err := newRouteClient(envOf(brokerEnv(map[string]string{"CF_API_TOKEN": "an-account-token"})))
	if err == nil || !strings.Contains(err.Error(), "unset CF_API_TOKEN") {
		t.Fatalf("want a refusal telling the operator to unset CF_API_TOKEN; got %v", err)
	}
	if strings.Contains(err.Error(), "an-account-token") {
		t.Error("the error leaked the token value")
	}
}

func TestNewRouteClient_BrokerURLMustBeHTTPSExceptForLoopback(t *testing.T) {
	for url, ok := range map[string]bool{
		"https://broker.example.com":  true,
		"https://broker.example.com/": true,
		"http://localhost:8787":       true,
		"http://127.0.0.1:8787":       true,
		"http://[::1]:8787":           true,
		"http://broker.example.com":   false, // credentials would cross the network in the clear
		"http://localhost.evil.com":   false,
		"ftp://broker.example.com":    false,
		"broker.example.com":          false,
		"https://":                    false,
		"":                            false,
	} {
		env := brokerEnv(map[string]string{"BROKER_URL": url})
		_, _, err := newRouteClient(envOf(env))
		if ok && err != nil {
			t.Errorf("BROKER_URL %q: unexpected error %v", url, err)
		}
		if !ok && err == nil {
			t.Errorf("BROKER_URL %q: want an error", url)
		}
	}
}

func TestNewRouteClient_ErrorsNeverContainTheSecret(t *testing.T) {
	env := brokerEnv(map[string]string{"BROKER_URL": "http://broker.example.com"})
	_, _, err := newRouteClient(envOf(env))
	if err == nil {
		t.Fatal("want an error")
	}
	if strings.Contains(err.Error(), "very-secret-value") {
		t.Errorf("the error leaked the client secret: %v", err)
	}
}

// The broker client must authenticate with the Access service-token headers and send NO bearer
// token, and must address Cloudflare's own paths under the broker's base URL.
func TestNewRouteClient_BrokerClientSendsAccessHeadersAndNoBearerToken(t *testing.T) {
	var gotPath string
	var gotHeader http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotHeader = r.URL.Path, r.Header.Clone()
		_, _ = w.Write([]byte(`{"success":true,"result":[],"result_info":{"page":1,"per_page":100,"count":0,"total_count":0}}`))
	}))
	defer srv.Close()

	// A trailing slash on BROKER_URL must not produce a double slash in the path.
	client, _, err := newRouteClient(envOf(brokerEnv(map[string]string{"BROKER_URL": srv.URL + "/"})))
	if err != nil {
		t.Fatalf("newRouteClient: %v", err)
	}
	if _, err := client.ListHostnameRoutes(context.Background(), ""); err != nil {
		t.Fatalf("ListHostnameRoutes: %v", err)
	}

	if gotPath != "/accounts/acct1/zerotrust/routes/hostname" {
		t.Errorf("path = %q, want Cloudflare's path directly under the broker URL", gotPath)
	}
	if got := gotHeader.Get("CF-Access-Client-Id"); got != "client-x.access" {
		t.Errorf("CF-Access-Client-Id = %q", got)
	}
	if got := gotHeader.Get("CF-Access-Client-Secret"); got != "very-secret-value" {
		t.Errorf("CF-Access-Client-Secret = %q", got)
	}
	if got := gotHeader.Get("Authorization"); got != "" {
		t.Errorf("Authorization = %q, want none: this instance holds no account token", got)
	}
}
