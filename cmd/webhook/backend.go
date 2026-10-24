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
	"fmt"
	"net/url"
	"strings"

	"github.com/arustydev/external-dns-cloudflare-zerotrust-provider/internal/cloudflare"
)

// Route backends: where hostname-route calls go.
const (
	// backendCloudflare talks to Cloudflare directly with an account API token.
	backendCloudflare = "cloudflare"
	// backendBroker talks to the route broker (see broker/), which holds the account token and
	// applies a per-instance policy. The instance never holds an account token.
	backendBroker = "broker"
)

// newRouteClient builds the Cloudflare client for the configured ROUTE_BACKEND. It returns the
// backend it chose so the caller can log it. It reads the environment through getenv so it can be
// tested without touching the process environment.
//
// The broker backend refuses to start if CF_API_TOKEN is also set. Its whole purpose is that no
// account-wide token reaches this cluster; running with both would keep the exposure while looking
// as though it had been removed.
func newRouteClient(getenv func(string) string) (*cloudflare.Client, string, error) {
	backend := strings.ToLower(strings.TrimSpace(getenv("ROUTE_BACKEND")))
	if backend == "" {
		backend = backendCloudflare
	}
	accountID := strings.TrimSpace(getenv("CF_ACCOUNT_ID"))
	if accountID == "" {
		return nil, "", fmt.Errorf("CF_ACCOUNT_ID is required")
	}

	switch backend {
	case backendCloudflare:
		token := getenv("CF_API_TOKEN")
		if token == "" {
			return nil, "", fmt.Errorf("CF_API_TOKEN is required when ROUTE_BACKEND=%s", backendCloudflare)
		}
		return cloudflare.New(accountID, token), backend, nil

	case backendBroker:
		if getenv("CF_API_TOKEN") != "" {
			return nil, "", fmt.Errorf("CF_API_TOKEN is set, but ROUTE_BACKEND=%s exists so this instance holds no "+
				"account token: unset CF_API_TOKEN", backendBroker)
		}
		brokerURL := strings.TrimSpace(getenv("BROKER_URL"))
		clientID := getenv("BROKER_CLIENT_ID")
		clientSecret := getenv("BROKER_CLIENT_SECRET")
		for name, value := range map[string]string{
			"BROKER_URL": brokerURL, "BROKER_CLIENT_ID": clientID, "BROKER_CLIENT_SECRET": clientSecret,
		} {
			if value == "" {
				return nil, "", fmt.Errorf("%s is required when ROUTE_BACKEND=%s", name, backendBroker)
			}
		}
		if err := checkBrokerURL(brokerURL); err != nil {
			return nil, "", err
		}
		return cloudflare.New(accountID, "",
			cloudflare.WithBaseURL(strings.TrimRight(brokerURL, "/")),
			cloudflare.WithHeader("CF-Access-Client-Id", clientID),
			cloudflare.WithHeader("CF-Access-Client-Secret", clientSecret),
		), backend, nil

	default:
		return nil, "", fmt.Errorf("ROUTE_BACKEND must be %q or %q, got %q", backendCloudflare, backendBroker, backend)
	}
}

// checkBrokerURL requires https, because the request carries Access service-token credentials, and
// allows plain http only to a loopback address so the broker can be tried locally.
func checkBrokerURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("BROKER_URL %q is not a valid URL", raw)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		switch u.Hostname() {
		case "localhost", "127.0.0.1", "::1":
			return nil
		}
	}
	return fmt.Errorf("BROKER_URL must be https (plain http is accepted only for localhost), got %q", u.Scheme+"://"+u.Host)
}
