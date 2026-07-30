# Upstream gap: `--dry-run` is silently inert for `--provider=webhook`

This is a **ready-to-file issue draft** against
[kubernetes-sigs/external-dns](https://github.com/kubernetes-sigs/external-dns). It is kept in
this repo rather than filed, so the citations stay next to the code they justify
(`DRY_RUN` in `internal/provider/provider.go`). File it if and when you want to.

Verified against `sigs.k8s.io/external-dns v0.21.0`.

## Why this matters to users of this provider

ExternalDNS logs `running in dry-run mode. No changes to DNS records will be made.` and then
makes them. For a webhook provider the flag is inert, so `--dry-run` is **not** a safe way to
validate against a live Cloudflare account.

This bit us for real: a `--dry-run` reconcile created a live Zero Trust hostname route on a
production tunnel (route `4521aa4d-775c-4ae3-a43a-eedb1b3de925`, `2026-07-29T17:37:39Z`).

Hence `DRY_RUN` in this provider — see the README's *Dry run* section. It is the only thing
that actually suppresses mutations.

---

## Issue draft (paste below the line)

**Title:** `--dry-run` is silently inert for `--provider=webhook`

**What happened**

With `--provider=webhook --dry-run`, external-dns logs that no changes will be made, then the
webhook provider applies them. The flag has no effect on the webhook path, so an operator who
uses `--dry-run` to validate against a live account mutates it instead.

**Why (v0.21.0 source)**

1. `controller/execute.go:67` — the flag only *logs*:

   ```go
   if cfg.DryRun {
       log.Info("running in dry-run mode. No changes to DNS records will be made.")
   }
   ```

2. The controller never gates `Registry.ApplyChanges` on `cfg.DryRun`. Dry-run is implemented
   **per provider** — `provider/aws`, `provider/azure`, `provider/cloudflare`,
   `provider/coredns`, `provider/akamai` and others each consult `DryRun` internally.

3. `provider/factory/provider.go:109` maps the webhook provider to its constructor:

   ```go
   externaldns.ProviderWebhook: webhook.New,
   ```

4. `provider/webhook/webhook.go:107` — `cfg.DryRun` is **never passed on**:

   ```go
   func New(ctx context.Context, cfg *externaldns.Config, _ *endpoint.DomainFilter) (provider.Provider, error) {
       return newProvider(ctx, cfg.WebhookProviderURL, cfg.WebhookProviderReadTimeout, cfg.WebhookProviderWriteTimeout)
   }
   ```

   `grep -r DryRun provider/webhook/` returns **nothing** — the package has no concept of it.

Because every other provider honours the flag, the webhook path is the one place where the
log line is actively misleading.

**Impact**

Webhook providers are the extension point for anything not in-tree, and they are precisely the
providers whose blast radius the maintainers cannot review. Silently inert `--dry-run` turns a
safety flag into a footgun, and each webhook provider must now re-implement dry-run itself and
document that the upstream flag does not work.

**Possible fixes** (either resolves it; the second fixes the whole class)

1. Pass it through — have `webhook.New` forward `cfg.DryRun` to the `WebhookProvider` and have
   `ApplyChanges` return `nil` early when set. Smallest change, webhook-local.
2. Gate centrally — have the controller skip `Registry.ApplyChanges` when `cfg.DryRun` is set,
   making the flag provider-independent and removing the duplicated per-provider handling.
   Behaviour-preserving for providers that already honour it.

A third, cheaper mitigation if neither is desired: make the log line conditional on the
provider actually supporting dry-run, so the flag never claims protection it is not providing.
