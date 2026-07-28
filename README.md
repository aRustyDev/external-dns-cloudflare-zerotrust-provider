# external-dns-cloudflare-zerotrust-provider

An [ExternalDNS](https://github.com/kubernetes-sigs/external-dns) **webhook provider** that
manages **Cloudflare Zero Trust private hostname routes** from Kubernetes Service annotations.

Annotate a Service with a private hostname and this provider creates the corresponding
[Zero Trust hostname route](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/)
binding that hostname to a Cloudflare Tunnel — so the name resolves for WARP clients over the
resolve-through-tunnel path — and removes it when the Service goes away.

> **Status: alpha.** Interfaces and defaults may change. Validate with `--policy=upsert-only`
> before enabling deletes.

## Scope — read this first

A private `<name>.woven` name needs **two** independent things to resolve over WARP:

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
  /hostname: foo.woven            (localhost:8888)            /accounts/{id}/zerotrust/routes/hostname
```

A Cloudflare Tunnel has the canonical target `<tunnel-id>.cfargotunnel.com`. The provider models
every managed hostname as a **CNAME endpoint** to that target, so ExternalDNS produces stable
plan diffs; `ApplyChanges` translates Create/Delete into hostname-route CRUD on the tunnel.

## Install

```sh
# 1) Credentials (scoped API token: Account > Cloudflare Tunnel : Edit)
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
| `CF_TUNNEL_ID` | yes | — | Tunnel the hostname routes bind to (one tunnel per instance) |
| `DOMAIN_FILTER` | no | — | Comma-separated suffixes to manage (e.g. `woven`) |
| `OWNER_ID` | no | `default` | Tags created routes' `comment` (`managed-by=external-dns/<id>`) |
| `WEBHOOK_LISTEN` | no | `127.0.0.1:8888` | Webhook API listen address (localhost-only by design) |
| `HEALTH_LISTEN` | no | `0.0.0.0:8080` | Health endpoints (`/healthz`, `/readyz`) |

### ExternalDNS flags that matter

- `--provider=webhook` and (implicitly) `--webhook-provider-url=http://localhost:8888`.
- `--registry=noop` — **required**: Zero Trust routes can't store TXT ownership records.
- `--policy=sync` to allow deletes; `--policy=upsert-only` while validating.
- One tunnel per instance — run additional instances for additional tunnels.

## Development

```sh
make build   # go build ./...
make test    # go test -race ./...
make docker  # container image
```

Built against `sigs.k8s.io/external-dns v0.21.0` (imported as a library; the stock ExternalDNS
image is the core, this binary is the sidecar).

## License

[Apache-2.0](LICENSE).
