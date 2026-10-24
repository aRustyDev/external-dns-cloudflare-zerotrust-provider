# Route broker

A Cloudflare Worker that sits between instances of the provider and Cloudflare's hostname-routes
API. It holds the account-wide Cloudflare token, so no cluster has to, and it gives each instance a
view of Cloudflare limited to its own tunnels and hostnames.

Design, threat model and the measurements behind it: [`docs/multi-tunnel-lifecycle.md`](../docs/multi-tunnel-lifecycle.md),
section 7.

## Why it exists

Cloudflare cannot scope an API token to one tunnel. Every tunnel, connector and Networks permission
group accepts only the whole account as its scope (measured, section 8 row 2 of the design doc). The
provider's token therefore has write access to **every** hostname route in the account, and anyone
who compromises one cluster gets all of them.

With the broker, an instance holds only an Access service token. The broker holds the account token
and decides, per instance, what it may see and change.

## What it does

It serves Cloudflare's own paths and response envelope, so the provider's existing client works
unchanged against it.

| Request | What the broker does |
|---|---|
| `GET .../zerotrust/routes/hostname` | Lists only the instance's own tunnels' routes. Naming another tunnel is `403`. |
| `POST .../hostname` | Allowed only for the instance's tunnels and hostname suffixes, with its own owner tag. Cloudflare's `409` / `1108` for a taken hostname passes through untouched. |
| `PATCH .../hostname/{id}` | Looks the route up first. Allowed only if it is the instance's, and only to move it onto another of the instance's tunnels. |
| `DELETE .../hostname/{id}` | Looks the route up first. Allowed only if it is the instance's. |

A route that is not the instance's gets exactly the response a route that does not exist gets
(`404`, error `1107`), so route ids cannot be probed. Everything else is refused. Each decision is
logged as one JSON line that never contains a secret.

## Policy

One JSON object in the `POLICY` variable, keyed by the Access service token's **client id**. That
is the value the instance sends as `CF-Access-Client-Id`, and it is the `common_name` claim in the
JWT Access issues.

```json
{
  "abc123.access": {
    "owner": "cluster-a",
    "tunnels": ["<tunnel-id>"],
    "suffixes": ["apps.example.private"]
  }
}
```

- `tunnels`: the tunnels the instance may list, create on, retarget to, and patch or delete from.
  Include a tunnel while it is draining. A tunnel can belong to only one client.
- `suffixes`: the hostnames it may manage. A suffix matches itself and any subdomain, on whole
  labels, so `private` does not admit `evilprivate`. Suffixes may overlap between clients, which a
  hostname handoff needs.
- `owner` (optional): when set, every comment the instance writes must be exactly
  `managed-by=external-dns/<owner>`, which is the tag the provider writes for that `OWNER_ID`. This
  stops one instance creating a route that claims to belong to another.

The policy is validated when the Worker starts. An unknown key, an empty list, a wildcard suffix or
a tunnel assigned to two clients makes the Worker refuse every request with `500` rather than guess.

## Deploy

You need a Cloudflare account with Zero Trust (for Access) and permission to deploy Workers.

1. **Create one Access service token per instance** (Zero Trust, Access, Service credentials).
   Note each token's client id and secret. They go to that instance, and the client id goes in the
   policy.
2. **Deploy the Worker** from this directory with `npx wrangler deploy`.
3. **Set its secrets:**
   ```sh
   npx wrangler secret put CF_API_TOKEN     # see "The upstream token" below
   npx wrangler secret put CF_ACCOUNT_ID
   ```
4. **Put an Access application in front of it.** For a `workers.dev` address, enable Cloudflare
   Access from the Worker's Domains and Routes settings. Give the application a **Service Auth**
   policy that includes the service tokens from step 1, and copy the application's audience tag.
   Created through the API, that is a `self_hosted` application whose `domain` is the Worker's
   `<name>.<subdomain>.workers.dev` hostname and whose one policy has `decision: "non_identity"` and
   an `include` of each `service_token`. The audience tag is the application's `aud`.
5. **Set the variables** in `wrangler.jsonc` and deploy again: `ACCESS_TEAM_DOMAIN`
   (`<team>.cloudflareaccess.com`), `ACCESS_AUD` (the audience tag) and `POLICY`.
6. **Point each instance at it.** See "Using it" below.

### The upstream token

The Worker's `CF_API_TOKEN` needs only **Cloudflare One Networks Read and Write**, because it only
calls the hostname-routes endpoints. It does not need tunnel, connector or token permissions. It
cannot be narrower than the whole account, because Cloudflare offers nothing narrower, which is the
reason the broker exists. A token holding exactly those two permission groups on the account was
enough to list, create and delete routes through a live deployment.

## Using it

On each instance, instead of `CF_API_TOKEN`:

```
ROUTE_BACKEND=broker
BROKER_URL=https://<your-broker-address>
BROKER_CLIENT_ID=<the service token's client id>
BROKER_CLIENT_SECRET=<the service token's secret>
CF_ACCOUNT_ID=<the account id>
```

The instance **refuses to start** if `CF_API_TOKEN` is also set. The point is that no account-wide
token reaches the cluster, and running with both would keep the exposure while looking as though it
had been removed.

## Operating it

- **Add an instance:** create a service token, add it to the Access policy, add its entry to
  `POLICY`, deploy, and give the instance its settings.
- **A tunnel or suffix changed:** change the instance's configuration and the policy together. A
  mismatch is loud, not silent: the broker answers `403` and the provider reports the host as failed
  or pending.
- **Rotate an instance's credential:** create a new service token, switch the instance over, then
  delete the old one and update the policy key.
- **If the broker is down**, the provider's `Records` call fails, and ExternalDNS aborts that whole
  reconcile cycle. Existing routes keep serving; only changes stall.
- **Logs:** one line per decision with the client id, operation, status, hostname and tunnel. A
  `denied` event with `unauthenticated` means a request reached the Worker without a valid Access
  JWT, which should not happen when Access is in front of it.
- **Cloudflare error `1010` from a client** is the Browser Integrity Check refusing its
  `User-Agent`, before Access or the Worker see the request. The provider names itself; a script
  calling the broker needs to send a `User-Agent` that is not its HTTP library's default.
- **Cloudflare error `1101`** is the Worker throwing. Look at its logs (`wrangler tail`).

## Tests

No dependencies are installed. Node 24 runs TypeScript directly.

```sh
node --test test/*.test.ts                 # unit tests: policy, Access JWT, handler
npx --yes -p typescript@5.9.3 tsc -p .     # typecheck
go test ./test/broker/                     # from the repo root: the real Go client and provider against this code
```

The Go end-to-end test runs the real handler behind a small local server, with only Cloudflare faked.
It is `e2e/serve.ts`, which **trusts a client-id header as identity and must never be deployed**.

`test/integration/broker_live_test.go` (build tag `integration`) is the same contract against a real
deployment: the Worker, a real Access application and the real Cloudflare API. Its header lists the
environment it needs. It never reads `CF_API_TOKEN`, so nothing it does holds the account token.

## What is and is not verified

- **Verified by tests:** every policy rule, every refusal and redaction, the pass-through of
  Cloudflare's `409` / `1108`, that no secret is logged and the caller's credentials are never
  forwarded, JWT signature, issuer, audience, expiry and algorithm checks (with real RSA keys), and
  the contract with the Go client and provider, including the provider's owner tag against the
  policy.
- **Verified live on 2026-10-23**, on a throwaway deployment in a real account that was torn down
  afterwards (`TestLiveBrokerThroughAccess`, seven subtests, all passing). The Worker ran in the
  Workers runtime, and a real Access application accepted a service token and passed the Worker a
  JWT it accepted: the signature against the team's real keys, the issuer, the audience, and a
  `common_name` equal to the service token's client id, which is the policy key. Through it, a
  client listed only its own routes, the provider created a route, a second client could neither see
  nor delete it (`404` / `1107`), naming another client's tunnel was refused (`403`), and a hostname
  another client held came back as Cloudflare's own `409` / `1108`, which the provider treated as
  pending without the holder appearing in its log. A request with no service token was answered
  `403` by Access and never reached the Worker.
- **Found only by that run, and fixed.** The first deployment answered every request with
  Cloudflare error `1101`: the handler called `deps.fetch(...)`, and the Workers runtime throws
  `Illegal invocation` for a `fetch` called as a method of another object, which Node does not, so no
  unit test could see it. The handler now calls it detached, and a test mimics the runtime's check
  (a mutation that restores the method call fails it). The run also showed Cloudflare's Browser
  Integrity Check refusing a Python client's default `User-Agent` with error `1010`; the provider's
  client now sends a named one. Whether Go's default `User-Agent` would have been refused as well
  was not tested.
- **Still not verified:** a successful `PATCH` (retarget) through the broker, since the live run only
  exercised refused ones; a key rotation on Access's side picked up by the Worker; a list of hundreds
  of routes (paging was only run against the fake); load; and a deployment that outlives a
  three-hour run, including rotating its secrets.
- **Not covered:** a compromised Worker or its secrets, an administrator of the Cloudflare account,
  and an instance abusing the access its own policy grants. There is no rate limiting. The broker
  is a single point of failure for changes.
