# Multi-tunnel, multi-instance route lifecycle

How several instances of this provider share one Cloudflare account: how a hostname moves between
them, how dead routes are cleaned up, and how they avoid stepping on each other.

**Status.** Sections 1 to 7 and 9 describe behavior that exists today, except that the broker in
section 7 has been tested but not deployed to a Workers runtime. Section 8 records what a live run
on 2026-10-23 measured: all six questions about Cloudflare's behavior are answered. The
sixth, whether a token bound to one tunnel is enforced on hostname routes, was answered by
Cloudflare's own permission catalog instead of the scoped-token test: no permission can be bound to
one tunnel, so that test cannot be run. Section 7 describes the broker that provides isolation
instead.

## 1. Scope and operator invariants

N instances share one account. Each has its own `OWNER_ID`, runs in its own cluster, and manages
its own tunnel or tunnels. Every route an instance creates carries the comment
`managed-by=external-dns/<OWNER_ID>`, and that tag is the only record of who owns it, because
ExternalDNS runs with `--registry=noop`.

The provider cannot check these from inside one instance, so the operator must hold them:

1. **`OWNER_ID` is unique per instance.** Two instances sharing one treat each other's routes as
   their own and delete them under `--policy=sync`. The provider warns at startup when it is still
   `default`.
2. **A non-strict instance is the only writer of untagged routes on its tunnels.**
3. **With `TUNNEL_MAP` and `COREDNS_CONFIGMAP` both set, every mapped tunnel terminates in the
   cluster this instance writes CoreDNS for.** The rewrite lives in one cluster and the route picks
   the tunnel.

What the provider enforces itself: a route tagged by a different owner is never read back, deleted
or retargeted, in either ownership mode. This mirrors `adopt`, which already refused to claim such
a route.

## 2. How a hostname resolves

A private hostname needs two legs:

1. A Cloudflare hostname route binding the name to a tunnel.
2. A CoreDNS rewrite, in the cluster that tunnel lands in, mapping the name to a Service's
   cluster-local name.

Gateway sends the query through the tunnel named by the route, and cloudflared resolves it with its
host's resolver. So the rewrite must live in the cluster whose tunnel the route names. A rewrite in
any other cluster is unreachable from WARP until the route moves there.

Cloudflare allows one route per hostname in the whole account and refuses a second with `HTTP 409`
and error `1108`, whichever tunnel holds the first. Two consequences drive the design:

- **The 409 is the mutex between instances.** There is no split-brain to prevent, only a state to
  wait out.
- **Learning that a name is held needs no read access.** The refusal itself says so. It reveals only
  that the hostname exists, which is inherent to an account-wide namespace.

## 3. Lifecycle, cycle by cycle

ExternalDNS runs `Records`, then `AdjustEndpoints`, then plans, then `ApplyChanges`, once per
`--interval`. The plan is computed from `Records`, so Cloudflare is its source of truth.

| Event | `--policy=sync` | `--policy=upsert-only` |
|---|---|---|
| Annotation added | Create route and rewrite. | Same. |
| Annotation removed | Delete route and remove rewrite. | Nothing. ExternalDNS never plans a delete. |
| Hostname renamed | Delete old and create new in one pass, deletes first. | Create new only. The old route stays. |
| Domain moved to another tunnel in `TUNNEL_MAP` | The route is retargeted in place. The old tunnel must be in `TUNNEL_DRAIN`. See section 5. | Same: ExternalDNS lets Updates through `upsert-only`. |

### One batch, one failure

`ApplyChanges` handles failures per host. A hostname that cannot be applied is reported and
skipped, and everything else in the batch still happens. The returned error joins the per-host
failures. Within a batch the order is: write the CoreDNS fragment in one apply, delete routes, then
create routes. The fragment still goes first and in one apply, because Cloudflare is the plan's
source of truth and writing it last means any failure leaves the plan able to re-issue the change.

Deletes go before creates so a name this instance gives up is released as early as possible. A
sibling waiting to claim it is blocked until the delete lands.

### Handing a hostname from instance X to instance Y

1. **Y's cycle.** `Records` lacks the host, so the plan creates it. Y stages the CoreDNS rewrite in
   its own cluster. The create returns 409, so the host is *pending*. Y's other changes proceed.
2. **The operator removes the annotation in X's cluster.** X must run `--policy=sync`. X deletes its
   route and its rewrite and never touches Y's tunnel. The name now fails to resolve.
3. **Y's next cycle**, at most one `--interval` later. The create succeeds. The rewrite was already
   staged, so CoreDNS reload latency is not on the critical path.

The gap runs from step 2 to step 3. Measured on 2026-10-23: a deleted route does not keep holding
its hostname, so nothing is added to that bound (section 8, row 3). Lower `--interval` on Y for the duration of a migration. Under
`upsert-only`, X never deletes, so the handoff never completes. That is the safe behavior while
validating.

### Two instances swapping hostnames

X holds `foo` and wants `bar`. Y holds `bar` and wants `foo`. Previously each instance hit a 409 on
its create and returned before reaching its delete, so neither released anything and both stalled
forever. Now X's create of `bar` is pending while its delete of `foo` still runs, Y claims `foo`,
and X's next cycle claims `bar`. It completes within two cycles of the first mover.

## 4. Pending conflicts

A create that Cloudflare refuses as already-routed is **pending**, not an error. It is logged,
counted in `cfzt_provider_routes_pending{reason}`, and retried every reconcile, because ExternalDNS
plans the create again each cycle. It does not fail `ApplyChanges`: returning it would make the
webhook answer 500 and raise ExternalDNS's error counters for as long as the handoff takes,
burying real failures.

The provider classifies the holder with one account-wide list per `ApplyChanges`, made lazily and
only when a create conflicts. If that list fails or cannot see the route, the reason is `unknown`
and the failure is counted in `cfzt_provider_list_errors_total{tunnel_id="account"}`; it never
fails the batch.

| `reason` | Meaning | Log hint | Clears when |
|---|---|---|---|
| `other` | Another external-dns owner holds it. | Says it will be created once that owner releases it. The owner id is logged only at debug level. | The holder deletes it. |
| `untagged` | A route with no owner tag holds it. | Names `ADOPT_UNTAGGED=true` when the route is on the wanted tunnel. | It is adopted, removed, or the holder moves it. |
| `self` | **This** owner routes it on a tunnel this instance does not list. | Names `TUNNEL_DRAIN`. Nothing will release it, because `Records` cannot see it. | The tunnel is added to `TUNNEL_DRAIN`, after which the route is retargeted, or the route is removed. |
| `unknown` | Refused, but no live holder was found. | Says it may be mid-delete, or on a tunnel this token cannot see. | The create lands. |

A pending host leaves the set on any of three pieces of evidence: its create succeeds, it appears
in `Records` as a route this instance manages, or it is no longer desired. The last two happen on
cycles where ExternalDNS plans nothing and never calls `ApplyChanges`, which is why they are
checked in `Records` and `AdjustEndpoints`. Without them the gauge would stick at its old value.

In dry run no create is attempted, so no conflict is observed and nothing is marked pending.

**Cost of staging the rewrite.** Y writes its CoreDNS rewrite before the create lands. In-cluster
clients in Y's cluster then resolve the name to Y's Service while WARP clients still reach X.
That is the price of keeping the handoff gap to one interval.

**An abandoned claim leaves a rewrite behind, and prune removes it.** If Y's annotation is removed
before X releases the name, the host is in neither `Records` nor the desired set, so no delete is
planned and nothing in the plan would remove the staged rewrite. CoreDNS prune (section 6) removes
it on the next reconcile. With `COREDNS_PRUNE=false` it stays until an operator removes it.

## 5. Draining a tunnel and retargeting a route

Two things used to go wrong when a tunnel changed, and both are handled now.

**A domain moved between tunnels in `TUNNEL_MAP`.** `Records` reports the route with its old
tunnel's target, `AdjustEndpoints` canonicalizes the desired host to the new tunnel's target, and
ExternalDNS plans an Update. That Update used to be dropped, so the route stayed on the old tunnel
silently. Now `ApplyChanges` retargets the owned route in place with a `PATCH`. The route keeps
its id, so there is no create/delete race and no gap in resolution. The CoreDNS rewrite does not
change, because both tunnels terminate in the same cluster (section 1).

- A route already on the wanted tunnel is left alone. That covers an Update planned for a TTL or
  label difference.
- A failed `PATCH` leaves the route on its old tunnel. `Records` still reports the old target, so
  the next cycle plans the same Update, and the retry is idempotent.
- One failing retarget does not stop the others.
- Only routes this instance may manage are retargeted (section 1).
- The request carries the documented full body: hostname, tunnel id and the existing comment.

**A tunnel removed from `TUNNEL_MAP` without draining.** `Records` no longer lists it, so the plan
creates each host again on the new tunnel and the create is refused as this owner's own route. It
is reported as `pending` with `reason="self"` and nothing will ever release it. `TUNNEL_DRAIN`
fixes this: tunnels this instance **lists and deletes from but never creates on**. `resolve` never
returns one, and a tunnel may not be both configured and draining.

Retire a tunnel by moving it to `TUNNEL_DRAIN`, watching
`cfzt_provider_routes_by_tunnel{tunnel_id}` until it reads zero, then removing it. That gauge counts
every live route this instance manages on the tunnel, including ones outside the domain filter,
because counting only in-filter routes would read zero while routes were still stranded.

**Verified live on 2026-10-23.** `PATCH` retargets a route in place and keeps its id, whether the
body is the full `{hostname, tunnel_id, comment}` or `tunnel_id` alone (section 8, row 1). The whole
path, through ExternalDNS's real planner, moved a route off a draining tunnel in one reconcile. The
delete-then-create fallback is therefore not needed and was not built.

**A tunnel cannot be deleted while it has routes.** Cloudflare refuses with `400` and error `1023`
until every route is removed (section 8, row 5), so draining a tunnel to zero is a precondition for
deleting it, and deleting a tunnel can never orphan its routes.

## 6. Pruning and orphan visibility

### CoreDNS prune, on by default

Remove fragment entries that nothing owns or wants. The key has exactly one writer, so such an entry
is stale by construction. This closes the leak in section 4 and the case of a route deleted out of
band. `COREDNS_PRUNE=false` turns it off.

An entry is removed only when all four hold. Each guard exists because dropping it makes prune
delete something it should not.

| Guard | What it protects |
|---|---|
| No live route this instance manages carries the host, on any listed tunnel, counted before the domain filter | A rewrite whose route exists, whether or not a Service currently wants it. This is also what keeps a rewrite under `upsert-only`, which never deletes the route. |
| No desired endpoint names the host | The staged rewrite of a host that is pending because another instance holds the name, and a host whose route is not created yet. |
| The host is inside `DOMAIN_FILTER` | Names this instance was never configured to manage. In single-tunnel mode the resolver accepts every hostname, so this is the only guard there. |
| The resolver still maps the host's domain to a tunnel | A domain that has left `TUNNEL_MAP`, whose routes may still exist on a tunnel that is no longer listed. |

Prune also waits for a **complete `Records`**. `Records` clears a completeness flag when it starts
and sets it only when it finishes, so a never-run or failed `Records` leaves the owned set unusable.
Without this a freshly started instance holds an empty owned set and would delete every rewrite
that is not currently wanted.

A failure to read or write the ConfigMap is logged and counted but does not fail
`AdjustEndpoints`. This is housekeeping, and a ConfigMap problem must not stop routes from being
created or deleted. In dry run it logs `would PRUNE stale CoreDNS rewrites` and counts the
suppression under `operation="prune"`.

### Visibility gauges

- `cfzt_provider_routes_undesired`: owned routes on a listed tunnel that no Service desires. Under
  `--policy=sync` the plan deletes them, so it reads near zero after each cycle with a one-cycle
  blip. Under `upsert-only` ExternalDNS never deletes them, so this is the only place they show.
- `cfzt_provider_routes_out_of_filter`: owned routes on a listed tunnel outside `DOMAIN_FILTER`.
  This instance never retargets or deletes these, so they only leave by hand.

Both log their hostnames once per change, not every reconcile.

### The `prune --owner <id>` subcommand

A dead instance cannot clean up after itself: its owner id was renamed, its cluster is gone, or a
tunnel was dropped from its configuration, so nothing inside the reconcile can reach those routes.
The operator runs `webhook prune --owner <id>` from the same image, with a token that covers that
owner's tunnels.

- **It looks by default.** Nothing is deleted without `--apply`.
- **Exact tag match.** It acts only on routes tagged `managed-by=external-dns/<id>`, using the
  provider's own `RouteTaggedBy`, so the tag format has one definition. `x` does not match `xy` or
  `x-prod`, and untagged routes and other owners' routes are never listed.
- **Scope.** `--tunnel` limits which tunnels are listed, repeatable or comma-separated, and with
  none it lists the whole account as far as the token can see. `--domain-filter` narrows further.
- **Failures.** A failed delete is reported and does not stop the rest. Exit status is `0` on
  success, `1` if a list or delete failed, `2` for bad usage. A failed list deletes nothing.
- **It removes Cloudflare routes only.** The dead instance's CoreDNS rewrites live in its own
  cluster.

Running it against a live instance's owner id is an outage window for every route it deletes,
because that instance recreates whatever it still desires on its next reconcile. The usage text and
the README both say so.

## 7. Token isolation: the route broker

### The problem

The provider's token needs Cloudflare One Networks write, which is an account-wide permission. Any
instance that holds it can read, change and delete **every** hostname route in the account, whatever
tunnel or owner it belongs to. Ownership tags keep a well-behaved instance out of other owners'
routes, but they are a convention the instance itself enforces. A compromised cluster is not bound
by it.

Section 8, row 2 shows Cloudflare gives no way around this. Every tunnel, connector and Networks
permission group accepts only the whole account as its scope, so no API token can be limited to one
tunnel or to one tunnel's routes.

### The design

A Cloudflare Worker holds the account token. Each instance holds only an Access service token, and
calls the Worker instead of Cloudflare.

```
instance X ──(Access service token)──▶ ┌────────────┐ ──(account token)──▶ Cloudflare
instance Y ──(Access service token)──▶ │   broker   │                      hostname-routes API
                                        └────────────┘
                                         policy: client → tunnels, suffixes, owner
```

- **Same API.** The broker serves Cloudflare's own paths and response envelope, so the provider's
  existing client works against it with a different base URL and different headers. Cloudflare's
  error codes and the decoding that relies on them, such as `1108` for a taken hostname, work
  unchanged.
- **Identity** is a verified Cloudflare Access JWT. Access checks the service token. The Worker then
  verifies the JWT itself (RS256 signature against the team's keys, issuer, audience, expiry) so a
  request that reached the Worker some other way is refused. Only a service token's identity, its
  `common_name` claim, is accepted.
- **Policy** maps each client to its tunnels, its hostname suffixes, and optionally its owner. It is
  validated at startup and anything ambiguous makes the Worker refuse everything.

### What the broker enforces

| Request | Rule |
|---|---|
| List | Only the client's own tunnels. Naming another tunnel is `403`. With none named, it lists the client's tunnels and nothing else, so an account-wide list through the broker is the client's own routes. |
| Create | The tunnel must be the client's, the hostname must be under one of its suffixes, and the comment must be exactly its owner tag when it has one. Only the three known fields reach Cloudflare. |
| Patch | The route must be the client's. It may move only onto another of the client's tunnels, and rename only within its suffixes. |
| Delete | The route must be the client's. |
| Anything else | Refused. |

**Redaction.** A route that is not the client's gets exactly the response a route that does not exist
gets, `404` with error `1107`, so route ids cannot be probed. A list never contains another client's
route.

**The conflict signal survives, and leaks nothing.** Cloudflare returns `409` with error `1108` when a
hostname is already routed, whichever tunnel holds it, and that response names no holder. The broker
passes it through untouched. The provider treats it as pending (section 4), and because its
account-wide lookup through the broker returns only its own routes, the reason is `unknown`. An
instance learns that a name is taken and nothing about who has it, which is the requirement.

### Using it

On the instance: `ROUTE_BACKEND=broker`, `BROKER_URL`, `BROKER_CLIENT_ID` and `BROKER_CLIENT_SECRET`
instead of `CF_API_TOKEN`. The instance refuses to start if `CF_API_TOKEN` is also set, because the
point is that no account-wide token reaches the cluster. Deployment and operation are in
[`broker/README.md`](../broker/README.md).

The Worker's own token needs only Cloudflare One Networks Read and Write. It cannot be narrower, which
is why the broker exists, but it is held by one Worker instead of by every cluster.

### Failure modes

| What fails | What happens |
|---|---|
| The broker is down | `Records` fails, so ExternalDNS aborts that whole reconcile cycle. Existing routes keep serving; only changes stall. |
| The policy disagrees with an instance's configuration | The broker answers `403`. The provider reports the host as a failed create, or fails the batch for a list, so it is loud. |
| The policy cannot be parsed | The Worker answers `500` to everything. It fails closed. |
| Access is misconfigured or bypassed | Requests without a valid JWT get `401`. |
| A key rotation at Access | An unknown key id triggers one refetch of the team's keys, at most once a minute. |

### What this does not protect against

- **A compromise of the Worker, its secrets, or an administrator of the Cloudflare account.** The
  account token still exists, in one place. The broker narrows who can reach it; it does not remove it.
- **An instance abusing the access its own policy grants.** It can still change its own routes.
- **Availability.** There is no rate limiting, and the broker is a single point of failure for changes.
- **A wrong policy.** The policy and each instance's `TUNNEL_MAP` are two sources of truth. A mismatch is
  loud, but nothing checks them against each other.

### What is verified, and what is not

- **Verified by tests:** every policy rule, every refusal and redaction, the pass-through of `409` /
  `1108`, that no secret is logged and no caller credential is forwarded, the JWT checks with real RSA
  keys, and the contract between the real Go client and provider and the real broker code, including
  that the provider's owner tag satisfies the broker's policy. Mutating each protection makes a test
  fail.
- **Verified against Cloudflare's documentation, not a live token:** the shape of a service token's JWT.
  `common_name` is the service token's client id, `sub` is empty, `iss` is
  `https://<team>.cloudflareaccess.com` and `aud` carries the application's tag.
- **Not verified:** the Worker has **not been deployed or run in the Workers runtime**, and no request
  has passed through a real Access application. It bundles (`wrangler deploy --dry-run`), but deploy it
  to a test account and run the provider against it before relying on it.

## 8. Live measurements (spike)

Six questions about Cloudflare's behavior shape this design. Each row below is either
`MEASURED <date>` with what was observed, or `UNVERIFIED` with the reason. **Nothing here is
inferred.** A row changes only when someone runs the test and pastes its `OBSERVED` lines.

The tests need throwaway tunnels and skip without them. They record what the API does, and none
of them fails because the API refused something. A token that cannot write hostname routes at all
makes them skip with that reason instead.

### What was measured (2026-10-23)

Two runs against an account that already held 10 tunnels and 76 hostname routes, some of them
production. Only tunnels and routes created for the runs were touched, and after each run the
account was verified back to 10 tunnels and 76 routes.

**Run 1, a token without a Networks permission.** It held Cloudflare One Connectors Read, Connector:
WARP Read and Write, and Connector: cloudflared Read and Write.

- Tunnels can be created and deleted with those permissions.
- Hostname routes can be listed (HTTP 200).
- Hostname routes cannot be created. Every `POST` returned `403` with error `10000`
  ("Authentication error"). The connector and cloudflared permissions do not authorize writing
  hostname routes; that needs a Cloudflare One Networks write permission, as the README already said
  for the older Tunnel permission.

**Run 2, the same token with Cloudflare One Networks Read and Write added.** Route creation worked
and every test that could run passed. The results are in the table.

**Operational note:** a permission added to the spike token took about 150 seconds to take effect.
The token endpoints returned `403` (error `9109`) for ten polls at 15-second intervals, then `200`.

**Also measured, read-only:** a hostname route can be fetched by id (`GET .../routes/hostname/{id}`
returns `200` with `id`, `hostname`, `tunnel_id` and `comment`), and an unknown id returns `404` with
error `1107`, "Hostname Route not found". The broker relies on both.

A data point for row 2, not its answer: a token holding cloudflared Write was refused hostname-route
creation, and creation worked only after an account-level Networks permission was added. That
suggests hostname-route writes are governed by the Networks permission rather than by tunnel
permissions. Row 2 still needs a token actually bound to one tunnel.

```sh
export CF_API_TOKEN=...  CF_ACCOUNT_ID=...   # the token needs Cloudflare One Networks write
export CF_TUNNEL_ID=...        # throwaway tunnel A
export CF_TUNNEL_ID_B=...      # throwaway tunnel B
export CF_API_TOKEN_SCOPED=... # row 2: an Account API Token bound to a role on tunnel A only
export CF_TUNNEL_ID_DISPOSABLE=...  # row 5: this tunnel is DELETED by the test
go test -tags=integration -v -count=1 \
  -run 'TestLive(RetargetPreservesRouteID|ScopedToken|SoftDelete|WildcardVsExact|TunnelDelete|ListFilters)' \
  ./test/integration/ | grep OBSERVED
```

| # | Question | Test | What the docs say | Result |
|---|---|---|---|---|
| 1 | Does `PATCH` with `tunnel_id` retarget a route and keep its id? Is a body with only `tunnel_id` accepted? | `TestLiveRetargetPreservesRouteID`, `TestLiveProviderRetargetsFromADrainingTunnel` | The teamnet routes API documents `tunnel_id` on update. Nothing found for hostname routes. | **MEASURED 2026-10-23.** A `PATCH` with the full body `{hostname, tunnel_id, comment}` moved a route from tunnel A to tunnel B: same route id, listed on B and no longer on A. A `PATCH` with only `{tunnel_id}` was also accepted and moved it back, same id. The whole provider path (`Records`, `AdjustEndpoints`, ExternalDNS's planner, `ApplyChanges`) retargeted a route off a draining tunnel in one reconcile, same id. |
| 2 | What can an API token bound to one tunnel do to hostname routes: list, create, patch and delete, on its own tunnel and on another? | `TestLiveScopedTokenHostnameRoutes` | Granular tunnel permissions shipped 2026-05-21. The enforced endpoints listed are `cfd_tunnel`, `warp_connector` and `teamnet/routes`. `zerotrust/routes/hostname` is not mentioned, and tokens are only said to "continue to function as before". | **MEASURED 2026-10-23, from the API.** No API token can be bound to one tunnel, so the test cannot be run. With Account API Tokens Read on the spike token, `GET /accounts/{id}/tokens/permission_groups` listed 413 permission groups. Every tunnel-related group (Cloudflare Tunnel, cloudflared, Connectors, WARP, Networks) has the single scope `com.cloudflare.api.account`, the whole account. The only narrower scopes in the catalog are zones, Flagship apps, Worker scripts and R2 buckets. The account owner saw the same in the dashboard, which offers no way to scope a token to specific tunnels. Cloudflare documents tunnel scoping only for member and permission policies. |
| 3 | After a route is deleted, how long does its hostname stay refused with `1108`? | `TestLiveSoftDeleteWindow` | Not documented. The API soft-deletes (`deleted_at`). | **MEASURED 2026-10-23.** No window. Re-creating a hostname straight after deleting its route succeeded on the first attempt, 704 ms after the delete returned, as a new route id. `1108` was never returned. A soft-deleted route does not hold the name. |
| 4 | How is a wildcard stored, and is an exact create under it on another tunnel refused? Which wins when a client resolves the name? | `TestLiveWildcardVsExact` | One leading wildcard label is allowed and stored without the `*`. Precedence against an exact route is undocumented. | **MEASURED 2026-10-23, API half.** A create for `*.<name>` succeeded and was stored as `<name>`, with the leading `*.` stripped. An exact create for `a.<name>` on a different tunnel then succeeded too, so a wildcard and an exact route can coexist and `1108` does not arbitrate between them. **UNVERIFIED:** which one wins when a client resolves the name, which needs a WARP client. |
| 5 | What happens to a tunnel's hostname routes when the tunnel is deleted? | `TestLiveTunnelDeleteCascade` | Not documented. | **MEASURED 2026-10-23.** No cascade. Deleting a tunnel that has a hostname route was refused: `400`, error `1023`, "This tunnel has private network routes. Please remove all routes before deleting the tunnel." The route stayed. A tunnel with no routes deleted normally. |
| 6 | Does the list endpoint filter by `hostname` and by `comment`? How long a comment is accepted? | `TestLiveListFiltersAndCommentLimit` | Neither a comment limit nor list filters are documented. | **MEASURED 2026-10-23.** Both filters work, on an exact match: `hostname=` returned exactly one route, and `comment=` returned exactly the routes carrying that comment. A 255-character comment was accepted and a 500-character one was refused with `400`, error `1112`, "Hostname Route comment cannot exceed 256 characters." |

**What each answer decided.**

- **Row 1:** retargeting is the in-place `PATCH` that exists today. The delete-then-create fallback
  was not needed and was not built.
- **Row 2:** decided section 7. Cloudflare cannot scope an API token to one tunnel, so native
  isolation is not available and isolation comes from a stateless broker in front of the account
  token (section 7). If Cloudflare later adds a tunnel-scoped permission,
  `TestLiveScopedTokenHostnameRoutes` answers whether it covers hostname routes, and the broker
  could be retired.
- **Row 3:** a handoff's gap is one reconcile interval and nothing more.
- **Row 4:** wildcards and exact routes can coexist across tunnels, so a wildcard can be taken by
  one instance without refusing another's exact route. See the known limitation in section 9 for
  what the stored form means for the provider.
- **Row 5:** a tunnel cannot be deleted until its routes are gone. Draining a tunnel to zero is the
  way to retire it, and a tunnel delete can never orphan routes.
- **Row 6:** the owner tag must fit in 256 characters. Its prefix `managed-by=external-dns/` is 24, so
  an `OWNER_ID` can be at most 232 characters. A single-hostname lookup is also possible, which the
  409 classifier could use instead of listing the account.

## 9. Not built, and why

- **Rolling back a staged rewrite on a conflict.** Rejected. The rewrite is written again on the
  next reconcile, so rollback costs two ConfigMap writes and a CoreDNS reload per pending host per
  cycle. Keep it staged and garbage-collect it (section 6).
- **A fast-retry loop inside the provider.** A webhook cannot trigger ExternalDNS reconciles, and a
  loop that creates from a stale snapshot can create a route for a Service that was just removed.
  The gap is bounded by `--interval`, which the runbook lowers.
- **Wildcard hostnames are not supported, and they behave badly.** Cloudflare stores a wildcard
  `*.<name>` as `<name>` (section 8, row 4), so `Records` reports `<name>` and no desired `*.<name>`
  matches it. From reading the code, not from running it: under `--policy=sync` the plan would delete
  `<name>` and create `*.<name>` every reconcile, and under `upsert-only` the create would be
  refused as already routed and stay pending. With CoreDNS enabled a wildcard is refused up front,
  because an exact rewrite cannot answer it. Do not annotate wildcard hostnames until this is
  tested and handled.
- **Validating `OWNER_ID` length.** Cloudflare refuses a comment over 256 characters, so an owner id
  over 232 would fail every create with a `400`. Not built: owner ids are short in practice.
- **A hostname-filtered lookup in the 409 classifier.** The list endpoint supports `hostname=`
  (section 8), so the classifier could fetch one route instead of listing the account. Not built:
  it costs one list per `ApplyChanges` and only when a create conflicts.
- **A stateful claim registry (a Durable Object behind the broker).** The stateless broker in
  section 7 is built, for isolation. A registry is a different thing and is not needed for
  correctness: the 409 is the mutex, the comment is the ownership record, and an owner's own delete
  is consent. A registry would add deterministic first-come ordering among several claimants and a
  zero-gap release-and-retarget. Revisit only if the gap of one interval proves unacceptable.
