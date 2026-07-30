# external-dns-cloudflare-zerotrust-provider

An [ExternalDNS](https://github.com/kubernetes-sigs/external-dns) **webhook provider** that
manages **Cloudflare Zero Trust private hostname routes** from Kubernetes Service annotations.

Annotate a Service with a private hostname and this provider creates the corresponding
[Zero Trust hostname route](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/)
binding that hostname to a Cloudflare Tunnel — so the name resolves for WARP clients over the
resolve-through-tunnel path — and removes it when the Service goes away.

> **Status: alpha.** Interfaces and defaults may change. Validate with `--policy=upsert-only`
> before enabling deletes.

> [!WARNING]
> **ExternalDNS's `--dry-run` does NOT protect a webhook provider.** It logs `running in
> dry-run mode. No changes to DNS records will be made.` and then makes them — `cfg.DryRun`
> never reaches a webhook provider. Use this provider's own **`DRY_RUN=true`** instead. See
> [Dry run](#dry-run).

## Scope — read this first

A `<name>.private` name needs **two** independent things to resolve over WARP:

1. **A Cloudflare Zero Trust hostname route** binding the name to the tunnel — **this provider
   manages this half** (via the `zerotrust/routes/hostname` API).
2. **An in-cluster CoreDNS answer** (`<name> → <svc>.<ns>.svc.cluster.local`) so cloudflared can
   forward to the Service ClusterIP — **NOT managed here.** Handle it with a CoreDNS fragment,
   the ExternalDNS `coredns`/etcd source, or your existing mechanism.

Cloudflare's stock ExternalDNS provider manages *public DNS-zone records*, not Zero Trust
tunnel routes — which is why this webhook exists.

## How it works

```
Service annotation                ExternalDNS core            this webhook (sidecar)
external-dns.alpha.kubernetes.io  --provider=webhook   -->    POST/DELETE
  /hostname: foo.private            (localhost:8888)            /accounts/{id}/zerotrust/routes/hostname
```

A Cloudflare Tunnel has the canonical target `<tunnel-id>.cfargotunnel.com`. The provider models
every managed hostname as a **CNAME endpoint** to that target, so ExternalDNS produces stable
plan diffs; `ApplyChanges` translates Create/Delete into hostname-route CRUD on the tunnel.

## Install

```sh
# 1) Credentials. Scoped API token needs Account > Cloudflare One Networks : Edit.
#    (Cloudflare Tunnel : Edit alone is NOT enough — route creation 403s with error 10000.)
kubectl create namespace external-dns
kubectl -n external-dns create secret generic cf-zerotrust \
  --from-literal=CF_API_TOKEN=<scoped-token> \
  --from-literal=CF_ACCOUNT_ID=<account-id> \
  --from-literal=CF_TUNNEL_ID=<tunnel-id>

# 2) ExternalDNS + this webhook sidecar
kubectl apply -f deploy/deployment.yaml

# 3) Annotate a Service (see deploy/example-service.yaml)
```

## Configuration (webhook env vars)

| Env | Required | Default | Description |
|---|---|---|---|
| `CF_API_TOKEN` | yes | — | Scoped Cloudflare API token (preferred over a global key) |
| `CF_ACCOUNT_ID` | yes | — | Cloudflare account ID |
| `CF_TUNNEL_ID` | conditional | — | Single-tunnel mode: tunnel the hostname routes bind to. Required unless `TUNNEL_MAP` is set |
| `TUNNEL_MAP` | conditional | — | Multi-tunnel mode: `domain=tunnelID,...` (most-specific domain wins). Supersedes `CF_TUNNEL_ID` |
| `OWNER_ID` | no | `default` | Tags created routes' `comment` (`managed-by=external-dns/<id>`) |
| `OWNERSHIP_STRICT` | no | `true` | Only read back / delete routes carrying this `OWNER_ID` (see [Ownership](#ownership)) |
| `DRY_RUN` | no | `false` | Log intended route creates/deletes and make **no** mutating Cloudflare call (see [Dry run](#dry-run)) |
| `DOMAIN_FILTER` | no | — | Comma-separated suffixes to manage (e.g. `private`) |
| `WEBHOOK_LISTEN` | no | `127.0.0.1:8888` | Webhook API listen address (localhost-only by design) |
| `HEALTH_LISTEN` | no | `0.0.0.0:8080` | Health (`/healthz`, `/readyz`) **and** Prometheus `/metrics` |

### ExternalDNS flags that matter

- `--provider=webhook` and (implicitly) `--webhook-provider-url=http://localhost:8888`.
- `--registry=noop` — **required**: Zero Trust routes can't store TXT ownership records.
- `--policy=sync` to allow deletes; `--policy=upsert-only` while validating.
- `--publish-internal-services` — **required for `ClusterIP` Services.** Without it ExternalDNS
  silently skips them, and you get no route and no error. Most `.private` names front a
  ClusterIP Service, so you almost certainly need this.
- `--dry-run` — **does nothing here.** Use `DRY_RUN=true` on the webhook instead.

## Dry run

Set **`DRY_RUN=true`** on the webhook container to make `ApplyChanges` log every intended
create/delete and return without issuing a single mutating Cloudflare call. Read-only `list`
calls still happen, so the logged plan is a real diff against live state rather than a guess,
and misconfiguration (a hostname with no configured tunnel) still fails loudly.

```
level=INFO msg="dry run: would CREATE hostname route" hostname=foo.private tunnel_id=… comment=managed-by=external-dns/cluster-a
level=INFO msg="dry run: would DELETE hostname route" hostname=old.private route_id=…
```

Two metrics keep a dry-run deployment honest in **both** directions — the risk is not only
"I thought it was inert and it wasn't", but also "it has been inert for a month and nobody
noticed":

- `cfzt_provider_dry_run` — gauge, `1` while suppressing. Alert on it being `1` unexpectedly.
- `cfzt_provider_dry_run_skipped_total{operation}` — counter of suppressed mutations. Rising
  means this instance is being asked to change routes and declining, which is what makes the
  gauge actionable.

> **Why this exists.** ExternalDNS implements dry-run *per provider*, and the webhook path never
> receives `cfg.DryRun` — so `--dry-run` is silently inert for every webhook provider, not just
> this one. Full source citations, and a ready-to-file upstream issue draft, are in
> [`docs/upstream-dry-run-gap.md`](docs/upstream-dry-run-gap.md).

## Ownership

Every route this provider creates is tagged with a comment `managed-by=external-dns/<OWNER_ID>`.
With **`OWNERSHIP_STRICT=true` (the default)** the provider only ever *sees* (in `Records`) and
*deletes* routes carrying its own `OWNER_ID`. Routes created by Terraform, by hand, or by a
different owner are invisible to it and can never be deleted by it — important where an external
system is the declared sole owner of some routes. Set `OWNERSHIP_STRICT=false` only to
deliberately adopt/manage pre-existing routes regardless of their comment.

> Strict mode + `--policy=sync` is the safe production combination: deletes are enabled but
> confined to this instance's own routes.

## Multiple tunnels

Run one instance per tunnel, **or** set `TUNNEL_MAP` to serve several tunnels from one instance:

```
TUNNEL_MAP=apps.private=<tunnel-a>,private=<tunnel-b>
```

Each hostname is bound to the tunnel of its **longest matching domain suffix**, so
`svc.apps.private` → `tunnel-a` and `other.private` → `tunnel-b`. A hostname matching no configured
domain is skipped.

## Metrics

Prometheus metrics are exposed on the health port at `/metrics` (the sample manifest sets the
`prometheus.io/scrape` annotations):

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `cfzt_provider_api_requests_total` | counter | `operation` (`list`/`create`/`delete`), `result` (`success`/`error`) | Cloudflare API calls |
| `cfzt_provider_routes_created_total` | counter | — | Hostname routes created |
| `cfzt_provider_routes_deleted_total` | counter | — | Hostname routes deleted |
| `cfzt_provider_apply_duration_seconds` | histogram | — | `ApplyChanges` reconcile duration |
| `cfzt_provider_records_managed` | gauge | — | Managed routes seen on the last `Records()` |
| `cfzt_provider_dry_run` | gauge | — | `1` while `DRY_RUN` suppresses all mutations, else `0` |
| `cfzt_provider_dry_run_skipped_total` | counter | `operation` (`create`/`delete`) | Mutations suppressed by dry run |

## Development

```sh
make build   # go build ./...
make test    # go test -race ./...
make docker  # container image
```

Built against `sigs.k8s.io/external-dns v0.21.0` (imported as a library; the stock ExternalDNS
image is the core, this binary is the sidecar).

### Live integration test

`test/integration/` holds a **live** create → list → delete round-trip (raw client *and* full
provider path) against the real API, gated behind the `integration` build tag so `go test ./...`
never runs it. Point it at a **throwaway** tunnel with a scoped, deletable token; each test cleans
up after itself:

```sh
export CF_API_TOKEN=...   CF_ACCOUNT_ID=...   CF_TUNNEL_ID=...
go test -tags=integration -v -run TestLive ./test/integration/
```

## Releases & image

CI (`.github/workflows/`) gates every PR with `go build/vet/test -race`, **golangci-lint**, a
**gofmt** check, **govulncheck** (reachability-aware Go CVEs), **CodeQL** (Go SAST), and
**dependency review**; `govulncheck` and CodeQL also run weekly. Images build/push **multi-arch**
(`linux/amd64,arm64`) to **GHCR** on pushes to `main` (`:latest`, `:sha-…`) and on `vX.Y.Z`
tags (`:X.Y.Z`, `:X.Y`). Before signing, the pushed image is **Trivy-scanned** (fixable
HIGH/CRITICAL OS vulns gate the release). Images are **cosign-signed (keyless)** with **SLSA
provenance + SBOM** attestations, and a source SBOM (`sbom.spdx.json`) is attached to each GitHub
release. Cut a release by pushing a semver tag:

```sh
git tag v0.3.0 && git push origin v0.3.0   # builds, scans, signs, and drafts a GitHub release
```

`deploy/deployment.yaml` pins a released tag (not `:latest`). Bump the pin when you cut a new
release. If you want **unauthenticated** image pulls, make the GHCR package public once
(Package → Package settings → Change visibility → Public), or supply an `imagePullSecret`.

### Verifying the image

The image is signed keyless via GitHub Actions OIDC; verify the signature and inspect the
attached provenance/SBOM attestations:

```sh
IMG=ghcr.io/arustydev/external-dns-cloudflare-zerotrust-provider:0.3.0

# Signature (identity = this repo's release workflow):
cosign verify "$IMG" \
  --certificate-identity-regexp '^https://github.com/aRustyDev/external-dns-cloudflare-zerotrust-provider/\.github/workflows/release\.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# SLSA provenance / SBOM attestations attached by buildx:
docker buildx imagetools inspect "$IMG" --format '{{ json .Provenance }}'
docker buildx imagetools inspect "$IMG" --format '{{ json .SBOM }}'
```

## License

[Apache-2.0](LICENSE).
