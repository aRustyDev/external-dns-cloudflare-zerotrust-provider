# Multi-tunnel, multi-instance route lifecycle

How several instances of this provider share one Cloudflare account: how a hostname moves between
them, how dead routes are cleaned up, and how they avoid stepping on each other.

**Status.** Sections 1 to 6 and 9 describe behavior that exists today. Section 8 lists the open
questions about Cloudflare's behavior and the test that settles each; **none has been measured
yet**. Section 7 (token isolation) is not written until section 8's scoped-token row is answered.

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

The gap runs from step 2 to step 3. Lower `--interval` on Y for the duration of a migration. Under
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

**Not yet verified live.** That Cloudflare retargets on `PATCH`, keeps the route id, and accepts the
body above has not been run against an account. `TestLiveRetargetPreservesRouteID` in
`test/integration/` settles it, and also records whether a body with only `tunnel_id` is accepted.
If the API turns out not to retarget on `PATCH`, the fallback is a delete followed by a create in
the same pass, which opens a short gap.

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

## 8. Live measurements (spike)

Six questions about Cloudflare's behavior shape this design, and none has been answered against a
real account yet. Each row below is either `MEASURED <date>` with what was observed, or
`UNVERIFIED` with the reason. **Nothing here is inferred.** A row changes only when someone runs
the test and pastes its `OBSERVED` lines.

The tests need throwaway tunnels and skip without them. They record what the API does, and none
of them fails because the API refused something.

```sh
export CF_API_TOKEN=...  CF_ACCOUNT_ID=...
export CF_TUNNEL_ID=...        # throwaway tunnel A
export CF_TUNNEL_ID_B=...      # throwaway tunnel B
export CF_API_TOKEN_SCOPED=... # row 2: an Account API Token bound to a role on tunnel A only
export CF_TUNNEL_ID_DISPOSABLE=...  # row 5: this tunnel is DELETED by the test
go test -tags=integration -v -count=1 \
  -run 'TestLive(RetargetPreservesRouteID|ScopedToken|SoftDelete|WildcardVsExact|TunnelDelete|ListFilters)' \
  ./test/integration/ | grep OBSERVED
```

| # | Question | Test | What the docs say | Status |
|---|---|---|---|---|
| 1 | Does `PATCH` with `tunnel_id` retarget a route and keep its id? Is a body with only `tunnel_id` accepted? | `TestLiveRetargetPreservesRouteID` | The teamnet routes API documents `tunnel_id` on update. Nothing found for hostname routes. | UNVERIFIED: no Cloudflare credentials were available. |
| 2 | What can an API token bound to one tunnel do to hostname routes: list, create, patch and delete, on its own tunnel and on another? | `TestLiveScopedTokenHostnameRoutes` | Granular tunnel permissions shipped 2026-05-21. The enforced endpoints listed are `cfd_tunnel`, `warp_connector` and `teamnet/routes`. `zerotrust/routes/hostname` is not mentioned, and tokens are only said to "continue to function as before". | UNVERIFIED: no credentials, and no tunnel-scoped token to test with. |
| 3 | After a route is deleted, how long does its hostname stay refused with `1108`? | `TestLiveSoftDeleteWindow` | Not documented. The API soft-deletes (`deleted_at`). | UNVERIFIED: no credentials. |
| 4 | How is a wildcard stored, and is an exact create under it on another tunnel refused? Which wins when a client resolves the name? | `TestLiveWildcardVsExact` | One leading wildcard label is allowed and stored without the `*`. Precedence against an exact route is undocumented. | UNVERIFIED: no credentials. Resolution-time precedence also needs a WARP client, so this test can only answer the API half. |
| 5 | What happens to a tunnel's hostname routes when the tunnel is deleted? | `TestLiveTunnelDeleteCascade` | Not documented. | UNVERIFIED: no credentials, and it needs a disposable tunnel. |
| 6 | Does the list endpoint filter by `hostname` and by `comment`? How long a comment is accepted? | `TestLiveListFiltersAndCommentLimit` | Neither a comment limit nor list filters are documented. | UNVERIFIED: no credentials. |

**What each answer decides.**

- **Row 1** decides whether retargeting is the in-place `PATCH` that exists today, or needs the
  delete-then-create fallback described in section 5, which opens a short gap.
- **Row 2** decides section 7. If a token bound to one tunnel lists only its own routes, gets `409`
  for a hostname held elsewhere, and is refused (`403` or `404`) when it patches or deletes a
  foreign route, Cloudflare isolates tunnels natively and the work is a token recipe plus tests.
  If it can see or touch routes on tunnels it does not cover, isolation needs a stateless
  broker in front of the account token. Section 7 is not written until this row is answered.
- **Row 3** bounds every handoff: the gap is this window plus one reconcile interval.
- **Row 4** decides whether wildcard hostnames are safe to hand to another instance.
- **Row 5** decides whether retiring a tunnel by deleting it first would orphan or remove routes.
- **Row 6** decides whether the 409 classifier can look up one hostname instead of listing the
  whole account, and whether the comment tag can carry more than the owner id.

## 9. Not built, and why

- **Rolling back a staged rewrite on a conflict.** Rejected. The rewrite is written again on the
  next reconcile, so rollback costs two ConfigMap writes and a CoreDNS reload per pending host per
  cycle. Keep it staged and garbage-collect it (section 6).
- **A fast-retry loop inside the provider.** A webhook cannot trigger ExternalDNS reconciles, and a
  loop that creates from a stale snapshot can create a route for a Service that was just removed.
  The gap is bounded by `--interval`, which the runbook lowers.
- **A claim registry or broker (Worker plus Durable Object).** Not needed for correctness: the 409
  is the mutex, the comment is the ownership record, and an owner's own delete is consent. A broker
  would add deterministic first-come ordering among several claimants and a zero-gap
  release-and-retarget. Revisit only if the gap of one interval proves unacceptable, or if
  Cloudflare cannot scope an API token to a tunnel and the isolation in section 7 needs it.
