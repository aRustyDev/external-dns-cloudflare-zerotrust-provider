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

	"sigs.k8s.io/external-dns/provider/webhook/api"

	"github.com/arustydev/external-dns-cloudflare-zerotrust-provider/internal/cloudflare"
	cfprovider "github.com/arustydev/external-dns-cloudflare-zerotrust-provider/internal/provider"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	accountID := mustEnv(log, "CF_ACCOUNT_ID")
	apiToken := mustEnv(log, "CF_API_TOKEN")
	tunnelID := mustEnv(log, "CF_TUNNEL_ID")
	ownerID := envOr("OWNER_ID", "default")
	domainFilter := splitCSV(os.Getenv("DOMAIN_FILTER"))
	webhookListen := envOr("WEBHOOK_LISTEN", "127.0.0.1:8888")
	healthListen := envOr("HEALTH_LISTEN", "0.0.0.0:8080")

	client := cloudflare.New(accountID, apiToken)
	p, err := cfprovider.New(cfprovider.Config{
		Client:       client,
		TunnelID:     tunnelID,
		OwnerID:      ownerID,
		DomainFilter: domainFilter,
	})
	if err != nil {
		log.Error("configuration error", "err", err)
		os.Exit(1)
	}

	go serveHealth(log, healthListen)

	log.Info("starting webhook provider",
		"webhook", webhookListen, "health", healthListen,
		"tunnel_id", tunnelID, "account_id", accountID, "domain_filter", domainFilter)

	// Blocks. Serves GET /, GET /records, POST /records, POST /adjustendpoints.
	api.StartHTTPApi(p, nil, 5*time.Second, 10*time.Second, webhookListen)
}

func serveHealth(log *slog.Logger, addr string) {
	mux := http.NewServeMux()
	ok := func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }
	mux.HandleFunc("/healthz", ok)
	mux.HandleFunc("/readyz", ok)
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
