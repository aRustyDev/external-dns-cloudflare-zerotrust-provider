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
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/external-dns/provider/webhook/api"

	"github.com/arustydev/external-dns-cloudflare-zerotrust-provider/internal/cloudflare"
	"github.com/arustydev/external-dns-cloudflare-zerotrust-provider/internal/coredns"
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

	// Leg 2 (the in-cluster CoreDNS answer) is OPT-IN: it turns on only when COREDNS_CONFIGMAP
	// names a ConfigMap. Unset, the provider manages the Cloudflare route half only.
	fragment, err := buildFragment(log, envOr("COREDNS_CONFIGMAP", ""))
	if err != nil {
		log.Error("CoreDNS fragment configuration error", "err", err)
		os.Exit(1)
	}

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
		CoreDNS:         fragment,
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
		"adopt_untagged", adoptUntagged, "domain_filter", domainFilter,
		"coredns_configmap", envOr("COREDNS_CONFIGMAP", ""))

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

// buildFragment wires the optional CoreDNS leg. spec is "<namespace>/<name>" naming the fragment
// ConfigMap; an empty spec returns a nil writer, which disables leg 2 entirely.
//
// The return type is the INTERFACE, not *coredns.Fragment. Returning a typed nil would make
// Config.CoreDNS a non-nil interface holding a nil pointer, which reads as "leg 2 enabled" and
// panics on first use.
func buildFragment(log *slog.Logger, spec string) (cfprovider.FragmentWriter, error) {
	if strings.TrimSpace(spec) == "" {
		return nil, nil
	}
	namespace, name, ok := strings.Cut(spec, "/")
	if !ok || namespace == "" || name == "" {
		return nil, fmt.Errorf("COREDNS_CONFIGMAP must be <namespace>/<name>, got %q", spec)
	}

	// In-cluster first (the deployed case); fall back to a kubeconfig so the provider can be
	// exercised against a cluster from a workstation.
	restCfg, err := rest.InClusterConfig()
	if err != nil {
		restCfg, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			clientcmd.NewDefaultClientConfigLoadingRules(), nil).ClientConfig()
		if err != nil {
			return nil, fmt.Errorf("no in-cluster config and no usable kubeconfig: %w", err)
		}
		log.Info("using kubeconfig for the CoreDNS fragment (not running in-cluster)")
	}
	clientset, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return nil, fmt.Errorf("build kubernetes client: %w", err)
	}

	f, err := coredns.New(coredns.Config{
		API:           clientset.CoreV1().ConfigMaps(namespace),
		Name:          name,
		Key:           envOr("COREDNS_FRAGMENT_KEY", coredns.DefaultKey),
		FieldManager:  envOr("COREDNS_FIELD_MANAGER", coredns.DefaultFieldManager),
		ClusterDomain: envOr("CLUSTER_DOMAIN", coredns.DefaultClusterDomain),
	})
	if err != nil {
		return nil, err
	}
	log.Info("CoreDNS fragment enabled — this instance owns BOTH legs of every managed hostname",
		"configmap", spec, "key", f.Key())
	return f, nil
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
