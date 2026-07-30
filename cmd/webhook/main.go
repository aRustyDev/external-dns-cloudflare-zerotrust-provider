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

// Command webhook runs the ExternalDNS webhook provider for Cloudflare Zero Trust
// hostname routes. It is meant to run as a sidecar to the stock ExternalDNS container,
// which is launched with `--provider=webhook`.
package main

import (
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"sigs.k8s.io/external-dns/provider/webhook/api"

	"github.com/arustydev/external-dns-cloudflare-zerotrust-provider/internal/cloudflare"
	"github.com/arustydev/external-dns-cloudflare-zerotrust-provider/internal/metrics"
	cfprovider "github.com/arustydev/external-dns-cloudflare-zerotrust-provider/internal/provider"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	accountID := mustEnv(log, "CF_ACCOUNT_ID")
	apiToken := mustEnv(log, "CF_API_TOKEN")
	tunnelID := os.Getenv("CF_TUNNEL_ID")
	tunnelMap, err := parseTunnelMap(os.Getenv("TUNNEL_MAP"))
	if err != nil {
		log.Error("invalid TUNNEL_MAP", "err", err)
		os.Exit(1)
	}
	if tunnelID == "" && len(tunnelMap) == 0 {
		log.Error("set CF_TUNNEL_ID (single tunnel) or TUNNEL_MAP (domain=tunnel,...)")
		os.Exit(1)
	}

	ownerID := envOr("OWNER_ID", "default")
	ownershipStrict := envBool("OWNERSHIP_STRICT", true)
	dryRun := envBool("DRY_RUN", false)
	adoptUntagged := envBool("ADOPT_UNTAGGED", false)
	domainFilter := splitCSV(os.Getenv("DOMAIN_FILTER"))
	webhookListen := envOr("WEBHOOK_LISTEN", "127.0.0.1:8888")
	healthListen := envOr("HEALTH_LISTEN", "0.0.0.0:8080")

	reg := prometheus.NewRegistry()
	m := metrics.New()
	m.MustRegister(reg)

	client := cloudflare.New(accountID, apiToken)
	p, err := cfprovider.New(cfprovider.Config{
		Client:          client,
		TunnelID:        tunnelID,
		TunnelMap:       tunnelMap,
		OwnerID:         ownerID,
		OwnershipStrict: ownershipStrict,
		DryRun:          dryRun,
		AdoptUntagged:   adoptUntagged,
		DomainFilter:    domainFilter,
		Metrics:         m,
		Logger:          log,
	})
	if err != nil {
		log.Error("configuration error", "err", err)
		os.Exit(1)
	}

	go serveHealth(log, healthListen, reg)

	log.Info("starting webhook provider",
		"webhook", webhookListen, "health", healthListen,
		"tunnel_id", tunnelID, "tunnel_map", tunnelMap, "account_id", accountID,
		"owner_id", ownerID, "ownership_strict", ownershipStrict, "dry_run", dryRun,
		"adopt_untagged", adoptUntagged, "domain_filter", domainFilter)

	if dryRun {
		log.Warn("DRY_RUN=true: NO Cloudflare route will be created or deleted; " +
			"intended changes are logged only. Unset DRY_RUN to apply changes.")
	}
	if adoptUntagged {
		log.Warn("ADOPT_UNTAGGED=true: a create for a hostname that already has a route will " +
			"CLAIM that route by rewriting its comment, taking ownership from whatever created it " +
			"(e.g. Terraform). The route id and tunnel binding are unchanged, so DNS never breaks.")
	}

	// Blocks. Serves GET /, GET /records, POST /records, POST /adjustendpoints.
	api.StartHTTPApi(p, nil, 5*time.Second, 10*time.Second, webhookListen)
}

// serveHealth exposes liveness/readiness probes and the Prometheus /metrics endpoint.
func serveHealth(log *slog.Logger, addr string, reg *prometheus.Registry) {
	mux := http.NewServeMux()
	ok := func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }
	mux.HandleFunc("/healthz", ok)
	mux.HandleFunc("/readyz", ok)
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{Registry: reg}))
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Error("health server stopped", "err", err)
	}
}

func mustEnv(log *slog.Logger, key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Error("missing required environment variable", "key", key)
		os.Exit(1)
	}
	return v
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// envBool parses a boolean env var, returning def when unset. Accepts 1/t/true/yes/on
// (case-insensitive) as true and their negatives as false.
func envBool(key string, def bool) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "":
		return def
	case "1", "t", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// parseTunnelMap parses "domain=tunnelID,domain2=tunnelID2" into a map. An empty input
// yields a nil map (single-tunnel mode). Malformed pairs are an error.
func parseTunnelMap(s string) (map[string]string, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	out := map[string]string{}
	for _, pair := range strings.Split(s, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		domain, tid, found := strings.Cut(pair, "=")
		domain, tid = strings.TrimSpace(domain), strings.TrimSpace(tid)
		if !found || domain == "" || tid == "" {
			return nil, &parseError{pair: pair}
		}
		out[domain] = tid
	}
	return out, nil
}

type parseError struct{ pair string }

func (e *parseError) Error() string {
	return "expected domain=tunnelID, got " + e.pair
}
