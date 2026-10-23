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

// Package provider implements the ExternalDNS provider.Provider interface backed by
// Cloudflare Zero Trust private hostname routes.
//
// Mapping model: a Cloudflare Tunnel has the canonical target "<tunnel-id>.cfargotunnel.com".
// We represent every managed hostname as a CNAME Endpoint pointing at that target, so
// ExternalDNS's plan produces stable diffs. ApplyChanges then translates Create/Delete into
// Zero Trust hostname-route CRUD on the tunnel selected for each hostname (a single tunnel,
// or the most-specific match from a domain->tunnel map).
//
// Legs: a private name needs BOTH a Cloudflare hostname route AND an in-cluster CoreDNS answer.
// This provider always owns the route; it ALSO owns the CoreDNS answer when a fragment writer is
// configured (Config.CoreDNS), so one Service annotation drives both. With no fragment writer —
// the default — the CoreDNS half is left to whatever manages it today.
//
// Ownership: routes are tagged with a "managed-by=external-dns/<owner>" comment. In
// ownership-strict mode the provider only ever reads back and deletes routes carrying its own
// owner tag, so it cannot disturb routes created by Terraform or by hand — important where an
// external system (e.g. Terraform) is the declared sole owner of some `.private` routes. In every
// mode it leaves routes tagged by a DIFFERENT owner alone.
//
// Dry run: ExternalDNS's own --dry-run flag is silently INERT for webhook providers (see
// docs/upstream-dry-run-gap.md), so this provider implements its own DryRun, which is the only
// thing that actually protects a live Cloudflare account.
package provider

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"
	extprovider "sigs.k8s.io/external-dns/provider"

	"github.com/arustydev/external-dns-cloudflare-zerotrust-provider/internal/cloudflare"
	"github.com/arustydev/external-dns-cloudflare-zerotrust-provider/internal/metrics"
)

// recordType is the type we synthesize for every managed hostname route.
const recordType = endpoint.RecordTypeCNAME

// corednsReconcileTimeout bounds the CoreDNS-only repair performed from AdjustEndpoints. The
// ExternalDNS provider interface does not pass that method a request context, so an unbounded
// Kubernetes call there could wedge a webhook reconciliation indefinitely.
const corednsReconcileTimeout = 15 * time.Second

// managedByPrefix is the comment prefix stamped on every route this project creates.
const managedByPrefix = "managed-by=external-dns"

// FragmentWriter owns the in-cluster leg of a managed hostname: the CoreDNS answer mapping the
// name to a Service's cluster-local name. Optional — a nil FragmentWriter means this provider
// manages only the Cloudflare route half, which is the default.
//
// Exported so callers can hold one as an interface. That matters for more than tidiness: assigning
// a nil CONCRETE implementation to Config.CoreDNS would produce a non-nil interface and panic on
// first use, so a caller deciding at runtime whether to enable leg 2 must be able to name this
// type and keep its nil untyped.
type FragmentWriter interface {
	// ServiceTarget maps an ExternalDNS resource label to a cluster-local name.
	ServiceTarget(resource string) (string, error)
	// Apply adds and removes rewrites, returning the resulting set.
	Apply(ctx context.Context, add map[string]string, remove []string) (map[string]string, error)
	// Load returns the rewrites currently in the managed key. Prune reads it to find entries that
	// nothing owns or wants any more.
	Load(ctx context.Context) (map[string]string, error)
	// Key names the ConfigMap key being managed (for logs).
	Key() string
}

// routeAPI is the subset of the Cloudflare client the provider needs (interface for testability).
type routeAPI interface {
	ListHostnameRoutes(ctx context.Context, tunnelID string) ([]cloudflare.HostnameRoute, error)
	CreateHostnameRoute(ctx context.Context, hostname, tunnelID, comment string) (*cloudflare.HostnameRoute, error)
	PatchHostnameRouteComment(ctx context.Context, id, comment string) (*cloudflare.HostnameRoute, error)
	PatchHostnameRoute(ctx context.Context, id string, patch cloudflare.RoutePatch) (*cloudflare.HostnameRoute, error)
	DeleteHostnameRoute(ctx context.Context, id string) error
}

// Provider is the ExternalDNS provider for Cloudflare Zero Trust hostname routes.
type Provider struct {
	*extprovider.BaseProvider

	client          routeAPI
	resolver        *tunnelResolver
	ownerID         string
	ownershipStrict bool
	dryRun          bool
	adoptUntagged   bool
	coredns         FragmentWriter
	domainFilter    *endpoint.DomainFilter
	metrics         *metrics.Metrics
	log             *slog.Logger

	// recordsHosts is the provider-owned route snapshot returned by the most recent Records
	// call. ExternalDNS calls Records before AdjustEndpoints in every reconciliation; retaining
	// only the hostname lets AdjustEndpoints repair CoreDNS for an already-existing route even
	// when canonicalization makes the Cloudflare plan empty. The mutex keeps concurrent webhook
	// requests from observing a partially replaced snapshot.
	recordsHostsMu sync.RWMutex
	recordsHosts   map[string]struct{}
	// ownedHosts is every live route this instance may manage on a listed tunnel, counted BEFORE
	// the domain filter, from the most recent successful Records. recordsOK says that snapshot is
	// complete: Records clears it when it starts and sets it only when it finishes, so a failed or
	// never-run Records leaves it false and prune declines to act on a partial view.
	ownedHosts map[string]struct{}
	recordsOK  bool

	corednsPrune bool

	// The hostname sets the orphan reports last logged, so a change is logged once instead of on
	// every reconcile.
	reportMu        sync.Mutex
	lastUndesired   string
	lastOutOfFilter string

	// pending maps a lowercase hostname to why its create is being refused as already-routed
	// (a metrics.Pending* reason). See setPending for its lifecycle.
	pendingMu sync.Mutex
	pending   map[string]string
}

// Config configures a Provider.
type Config struct {
	Client routeAPI
	// TunnelID selects single-tunnel mode: every managed hostname is bound to this tunnel.
	TunnelID string
	// TunnelMap selects multi-tunnel mode (domain -> tunnel id). When non-empty it takes
	// precedence over TunnelID and a hostname is bound to the tunnel of its longest matching
	// domain suffix.
	TunnelMap map[string]string
	// TunnelDrain lists tunnels this instance still LISTS and deletes from but never creates on.
	// Move a tunnel here, instead of dropping it from the configuration, to retire it: its routes
	// stay visible, so a hostname moved to another tunnel is retargeted and a removed one deleted,
	// rather than the routes being orphaned. A tunnel may not also be configured.
	TunnelDrain []string
	// OwnerID tags managed routes and, in strict mode, scopes which routes are managed.
	OwnerID string
	// OwnershipStrict, when true, restricts Records()/deletes to routes this owner created.
	OwnershipStrict bool
	// DryRun, when true, makes ApplyChanges log every intended create/delete and return nil
	// WITHOUT issuing any mutating Cloudflare call. Read-only list calls still happen, so the
	// logged plan reflects live state. This exists because ExternalDNS's --dry-run does NOT
	// reach a webhook provider — see docs/upstream-dry-run-gap.md.
	DryRun bool
	// AdoptUntagged, when true, lets ApplyChanges CLAIM a pre-existing route for a hostname it
	// was asked to create — by PATCHing the route's comment to this owner's tag — instead of
	// failing. The route id, hostname and tunnel binding are untouched, so adoption causes no
	// DNS interruption. Off by default: adoption takes over a route another system created.
	AdoptUntagged bool
	// CoreDNS, when non-nil, makes the provider ALSO own the in-cluster CoreDNS answer for every
	// managed hostname, so one Service annotation drives both legs. Nil (the default) leaves the
	// CoreDNS half to whatever manages it today.
	CoreDNS FragmentWriter
	// CoreDNSPrune, when true and CoreDNS is set, removes fragment entries that nothing owns or
	// wants: no live route this instance manages, and no desired endpoint. The key has exactly one
	// writer, so such an entry is stale by construction. It closes the leak left when a pending
	// host's annotation is removed before the holder releases it, and when a route is deleted out
	// of band. Only hosts inside the domain filter that the resolver can still resolve are
	// considered, and nothing is pruned until a complete Records has run.
	CoreDNSPrune bool
	DomainFilter []string
	// Metrics is optional; nil disables metrics (all metric calls are no-ops).
	Metrics *metrics.Metrics
	// Logger is optional; nil uses slog.Default(). Dry-run reports are logged here, so a
	// discarding logger makes DryRun silent.
	Logger *slog.Logger
}

// New builds a Provider.
func New(cfg Config) (*Provider, error) {
	if cfg.Client == nil {
		return nil, fmt.Errorf("cloudflare client is required")
	}
	var resolver *tunnelResolver
	switch {
	case len(cfg.TunnelMap) > 0:
		r, err := newMapTunnelResolver(cfg.TunnelMap)
		if err != nil {
			return nil, err
		}
		resolver = r
	case cfg.TunnelID != "":
		resolver = newSingleTunnelResolver(cfg.TunnelID)
	default:
		return nil, fmt.Errorf("a tunnel id or a non-empty tunnel map is required")
	}
	if err := resolver.setDrain(cfg.TunnelDrain); err != nil {
		return nil, err
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	// Publish the gauge at construction so it reads correctly from the first scrape, not just
	// after the first reconcile.
	cfg.Metrics.SetDryRun(cfg.DryRun)
	cfg.Metrics.SetRoutesPending(nil)
	return &Provider{
		BaseProvider:    &extprovider.BaseProvider{},
		client:          cfg.Client,
		resolver:        resolver,
		ownerID:         cfg.OwnerID,
		ownershipStrict: cfg.OwnershipStrict,
		dryRun:          cfg.DryRun,
		adoptUntagged:   cfg.AdoptUntagged,
		coredns:         cfg.CoreDNS,
		domainFilter:    endpoint.NewDomainFilter(cfg.DomainFilter),
		metrics:         cfg.Metrics,
		log:             logger,
		pending:         map[string]string{},
		corednsPrune:    cfg.CoreDNSPrune,
	}, nil
}

// comment tags routes we manage so they are distinguishable from hand-created ones.
func (p *Provider) comment() string {
	if p.ownerID == "" {
		return managedByPrefix
	}
	return managedByPrefix + "/" + p.ownerID
}

// routeOwner parses a route comment. managed is true if the comment was written by this
// project (any owner); owner is the owner id ("" when the comment carries no owner).
func routeOwner(comment string) (owner string, managed bool) {
	c := strings.TrimSpace(comment)
	if c == managedByPrefix {
		return "", true
	}
	if rest, ok := strings.CutPrefix(c, managedByPrefix+"/"); ok {
		return rest, true
	}
	return "", false
}

// RouteTaggedBy reports whether a route comment carries the managed-by tag of the given owner.
// It exists so tools outside this package, such as the prune subcommand, never re-implement the
// tag format and drift from it.
func RouteTaggedBy(comment, owner string) bool {
	o, managed := routeOwner(comment)
	return managed && o == owner
}

// owns reports whether this provider instance owns the route (managed by us, our owner id).
func (p *Provider) owns(r cloudflare.HostnameRoute) bool {
	owner, managed := routeOwner(r.Comment)
	return managed && owner == p.ownerID
}

// manageable reports whether this instance may read back, delete or retarget the route.
//
// A route tagged by ANOTHER external-dns owner is never manageable, in any mode: that tag is the
// only record of who created it, and acting on it would let one instance delete a sibling's
// routes. A route carrying no tag at all (Terraform, hand-created) is manageable only when
// ownership-strict mode is off. Our own tag is always manageable. This mirrors adopt(), which
// refuses to claim another owner's route for the same reason.
func (p *Provider) manageable(r cloudflare.HostnameRoute) bool {
	owner, managed := routeOwner(r.Comment)
	if managed {
		return owner == p.ownerID
	}
	return !p.ownershipStrict
}

// Records lists managed hostname routes across the configured tunnel(s) as CNAME endpoints.
// It filters by domain filter and by ownership (see manageable).
func (p *Provider) Records(ctx context.Context) ([]*endpoint.Endpoint, error) {
	p.markRecordsIncomplete()
	var out []*endpoint.Endpoint
	owned := map[string]struct{}{}
	var outOfFilter []string
	// Routes this instance manages on each listed tunnel, counted BEFORE the domain filter and
	// including zeros. A draining tunnel reading 0 means it can be retired; counting only
	// in-filter routes would read 0 while out-of-filter routes were still stranded on it.
	perTunnel := map[string]int{}
	for _, tid := range p.resolver.tunnels() {
		perTunnel[tid] = 0
		routes, err := p.client.ListHostnameRoutes(ctx, tid)
		p.metrics.APIRequest(metrics.OpList, err)
		if err != nil {
			p.metrics.ListError(tid)
			return nil, err
		}
		target := p.resolver.target(tid)
		for _, r := range routes {
			if r.DeletedAt != nil {
				continue
			}
			if !p.manageable(r) {
				continue
			}
			perTunnel[tid]++
			owned[strings.ToLower(r.Hostname)] = struct{}{}
			if !p.domainFilter.Match(r.Hostname) {
				outOfFilter = append(outOfFilter, strings.ToLower(r.Hostname))
				continue
			}
			out = append(out, endpoint.NewEndpoint(r.Hostname, recordType, target))
		}
	}
	p.metrics.SetRoutesByTunnel(perTunnel)
	p.metrics.SetRecordsManaged(len(out))
	p.metrics.SetRoutesOutOfFilter(len(outOfFilter))
	p.logSetChange(&p.lastOutOfFilter, outOfFilter, "routes this instance owns are outside the "+
		"domain filter, so it will not retarget or delete them")
	p.rememberRecordHosts(out, owned)
	// A host that now appears here exists and is ours, so it is no longer waiting on anyone.
	exists := p.recordHosts()
	p.retainPending(func(host string) bool { _, ok := exists[host]; return !ok })
	return out, nil
}

// rememberRecordHosts records exactly the route names this provider exposed to ExternalDNS in
// the current reconciliation. In ownership-strict mode that means only routes carrying this
// provider's owner tag; CoreDNS is therefore never retargeted merely because some other writer
// happens to own the same Cloudflare hostname route.
//
// owned is every manageable live route on a listed tunnel before the domain filter. Calling this
// is what marks the snapshot complete, so it must be the last step of a successful Records.
func (p *Provider) rememberRecordHosts(records []*endpoint.Endpoint, owned map[string]struct{}) {
	hosts := make(map[string]struct{}, len(records))
	for _, ep := range records {
		hosts[strings.ToLower(ep.DNSName)] = struct{}{}
	}
	p.recordsHostsMu.Lock()
	p.recordsHosts = hosts
	p.ownedHosts = owned
	p.recordsOK = true
	p.recordsHostsMu.Unlock()
}

// markRecordsIncomplete clears the completeness flag at the start of Records.
func (p *Provider) markRecordsIncomplete() {
	p.recordsHostsMu.Lock()
	p.recordsOK = false
	p.recordsHostsMu.Unlock()
}

// ownedSnapshot returns a copy of the owned set and whether it came from a complete Records.
func (p *Provider) ownedSnapshot() (map[string]struct{}, bool) {
	p.recordsHostsMu.RLock()
	defer p.recordsHostsMu.RUnlock()
	if !p.recordsOK {
		return nil, false
	}
	owned := make(map[string]struct{}, len(p.ownedHosts))
	for host := range p.ownedHosts {
		owned[host] = struct{}{}
	}
	return owned, true
}

// logSetChange logs the sorted hostnames at Info, but only when the set differs from the one last
// logged under the same key. The gauges carry the count every cycle; this carries the names, once.
func (p *Provider) logSetChange(last *string, hosts []string, msg string) {
	sort.Strings(hosts)
	key := strings.Join(hosts, ",")
	p.reportMu.Lock()
	changed := key != *last
	*last = key
	p.reportMu.Unlock()
	if changed && len(hosts) > 0 {
		p.log.Info(msg, "count", len(hosts), "hostnames", hosts)
	}
}

// recordHosts returns a copy so a reconciliation never holds the cache lock while calling the
// Kubernetes API through the CoreDNS fragment writer.
func (p *Provider) recordHosts() map[string]struct{} {
	p.recordsHostsMu.RLock()
	defer p.recordsHostsMu.RUnlock()
	hosts := make(map[string]struct{}, len(p.recordsHosts))
	for host := range p.recordsHosts {
		hosts[host] = struct{}{}
	}
	return hosts
}

// AdjustEndpoints canonicalizes candidate endpoints so plan diffs are stable: everything we
// manage becomes a CNAME to the target of the tunnel selected for its hostname. Hostnames
// outside the domain filter, or with no matching tunnel, are dropped.
//
// Labels are carried across. endpoint.NewEndpoint does not copy them, and the ExternalDNS
// service source's "resource" label (service/<namespace>/<name>) is the ONLY channel through
// which ApplyChanges can learn which Service a hostname belongs to — needed to answer the name
// in-cluster, because a CoreDNS rewrite maps name->name, not name->IP.
//
// This cannot cause perpetual updates: the plan compares targets and TTL (plan.targetChanged),
// never labels; labels matter only to the TXT registry, which this provider cannot use.
func (p *Provider) AdjustEndpoints(endpoints []*endpoint.Endpoint) ([]*endpoint.Endpoint, error) {
	var out []*endpoint.Endpoint
	for _, ep := range endpoints {
		if !p.domainFilter.Match(ep.DNSName) {
			continue
		}
		target, ok := p.resolver.targetFor(ep.DNSName)
		if !ok {
			continue // no tunnel configured for this hostname's domain
		}
		adjusted := endpoint.NewEndpoint(ep.DNSName, recordType, target)
		for k, v := range ep.Labels {
			adjusted.Labels[k] = v
		}
		out = append(out, adjusted)
	}
	// A pending host whose annotation was removed is no longer waiting for anything. ExternalDNS
	// plans no create for it, so ApplyChanges would never run again to clear it.
	desired := make(map[string]struct{}, len(out))
	for _, ep := range out {
		desired[strings.ToLower(ep.DNSName)] = struct{}{}
	}
	p.retainPending(func(host string) bool { _, ok := desired[host]; return ok })
	// ExternalDNS deliberately ignores endpoint labels while calculating its route plan. That is
	// normally useful here: every desired endpoint canonicalizes to the same tunnel CNAME as an
	// existing route, so replacing a Service leaves the Cloudflare plan empty. The resource label
	// is nevertheless the desired state of leg 2. Reconcile only names seen in the preceding
	// Records snapshot: new routes and deletes retain ApplyChanges' existing "fragment first,
	// Cloudflare last" transaction, while an already-present route can still retarget CoreDNS.
	//
	// Provider.AdjustEndpoints has no context parameter. The webhook API does not expose the
	// request context to this interface, so use a bounded internal context. A fragment failure
	// must be returned so ExternalDNS retries the entire reconciliation rather than accepting a
	// silently stale in-cluster answer.
	ctx, cancel := context.WithTimeout(context.Background(), corednsReconcileTimeout)
	defer cancel()
	if err := p.reconcileExistingCoreDNS(ctx, out); err != nil {
		return nil, err
	}
	p.reportUndesired(desired)
	p.pruneCoreDNS(ctx, desired)
	return out, nil
}

// reportUndesired counts the routes this instance owns and lists on a tunnel that nothing desires
// any more. Under --policy=sync the plan deletes them, so it reads near zero after each cycle;
// under upsert-only ExternalDNS never deletes, so it is the only place they are visible.
func (p *Provider) reportUndesired(desired map[string]struct{}) {
	var undesired []string
	for host := range p.recordHosts() {
		if _, ok := desired[host]; !ok {
			undesired = append(undesired, host)
		}
	}
	p.metrics.SetRoutesUndesired(len(undesired))
	p.logSetChange(&p.lastUndesired, undesired, "routes this instance owns are no longer desired by any Service")
}

// pruneCoreDNS removes fragment entries that nothing owns or wants. See Config.CoreDNSPrune.
//
// An entry is removed only when ALL of these hold: no live route this instance manages carries the
// host (before the domain filter), no desired endpoint names it, it is inside the domain filter,
// and the resolver still maps its domain to a tunnel. The last two keep prune away from names this
// instance was never configured to manage, such as a domain that has left TUNNEL_MAP while its
// routes may still exist on a tunnel that is no longer listed.
//
// It runs only after a complete Records. Without that, a freshly started instance holds an empty
// owned set and would delete every rewrite that is not currently desired.
//
// A failure here is logged and counted but does not fail AdjustEndpoints: this is housekeeping, and
// a ConfigMap problem must not stop routes from being created or deleted.
func (p *Provider) pruneCoreDNS(ctx context.Context, desired map[string]struct{}) {
	if p.coredns == nil || !p.corednsPrune {
		return
	}
	owned, ok := p.ownedSnapshot()
	if !ok {
		return
	}
	current, err := p.coredns.Load(ctx)
	if err != nil {
		p.log.Warn("CoreDNS prune skipped: could not read the fragment", "key", p.coredns.Key(), "err", err)
		return
	}
	var remove []string
	for host := range current {
		if _, ok := owned[host]; ok {
			continue
		}
		if _, ok := desired[host]; ok {
			continue
		}
		if !p.domainFilter.Match(host) {
			continue
		}
		if _, ok := p.resolver.resolve(host); !ok {
			continue
		}
		remove = append(remove, host)
	}
	if len(remove) == 0 {
		return
	}
	sort.Strings(remove)
	if p.dryRun {
		p.log.Info("dry run: would PRUNE stale CoreDNS rewrites", "key", p.coredns.Key(), "remove", remove)
		p.metrics.DryRunSkipped(metrics.OpPrune)
		return
	}
	after, err := p.coredns.Apply(ctx, nil, remove)
	p.metrics.CoreDNSWrite(err)
	if err != nil {
		p.log.Warn("CoreDNS prune failed", "key", p.coredns.Key(), "err", err)
		return
	}
	p.metrics.SetCoreDNSRewrites(len(after))
	p.metrics.CoreDNSPruned(len(remove))
	p.log.Info("pruned stale CoreDNS rewrites: no route this instance manages and no Service wants them",
		"key", p.coredns.Key(), "removed", remove, "rewrites", len(after))
}

// GetDomainFilter exposes the configured domain filter to ExternalDNS.
func (p *Provider) GetDomainFilter() endpoint.DomainFilterInterface {
	return p.domainFilter
}

// ApplyChanges deletes, retargets and creates hostname routes to satisfy the plan. An Update is a
// retarget: ExternalDNS plans one when a hostname's tunnel target changed, which is what happens
// when TUNNEL_MAP moves its domain to another tunnel. The route is moved in place (see
// applyUpdates), keeping its id, so there is no create/delete race and no gap in resolution.
//
// Failures are PER HOST. A hostname that cannot be applied (no resource label, no tunnel for its
// domain, a refused adoption, an API error) is reported and skipped, and every other change in
// the batch still proceeds. The returned error joins the per-host failures.
//
// A create that Cloudflare refuses as "hostname already routed" (error 1108) is deliberately NOT
// a failure. It means another writer holds the name, which is the normal state of a handoff
// between two instances, so the host is recorded as pending: logged with the reason, counted in
// routes_pending, and retried on every reconcile because ExternalDNS plans it again. Returning
// it as an error would make the webhook answer 500 and push ExternalDNS's error counters up for
// as long as the handoff takes, burying real failures.
//
// Deletes run BEFORE creates, so a name this instance gives up is released as early as possible:
// a sibling waiting to claim it is blocked until the delete lands, and the creates can spend a
// while on API calls first. The per-host handling above is what removes the old deadlock, where
// two instances swapping hostnames each aborted on a 409 before reaching their delete; this
// ordering only shortens the wait. The CoreDNS fragment is still written first of all (see
// applyCoreDNS), so that ordering is unaffected.
//
// With AdoptUntagged enabled, a create whose hostname already has a route CLAIMS that route
// (comment PATCH) rather than failing — see adopt.
//
// In dry-run mode the gate sits at each mutating call rather than at the top of the function.
// That is deliberate: the domain filter, tunnel resolution, ownership filtering and the
// hostname->route-id lookup all still run, so the logged plan reflects what would really happen
// and misconfiguration (e.g. a hostname with no configured tunnel) still fails loudly. A create
// is never attempted in dry-run, so no conflict is observed and nothing is marked pending.
func (p *Provider) ApplyChanges(ctx context.Context, changes *plan.Changes) error {
	if changes == nil || (len(changes.Create) == 0 && len(changes.Delete) == 0 && len(changes.UpdateNew) == 0) {
		return nil
	}
	start := time.Now()
	defer func() { p.metrics.ObserveApply(time.Since(start).Seconds()) }()

	// Build hostname -> route from the live set once, for deletes and retargets. Only routes this
	// instance may manage are eligible (see manageable), so we never touch Terraform-owned,
	// hand-created or sibling-owned ones.
	var index map[string]cloudflare.HostnameRoute
	if len(changes.Delete) > 0 || len(changes.UpdateNew) > 0 {
		idx, err := p.ownedRouteIndex(ctx)
		if err != nil {
			return err
		}
		index = idx
	}

	// Adoption must see routes this instance does NOT own, so this index is built WITHOUT the
	// ownership filter (unlike the delete index above). Cloudflare rejects a duplicate hostname
	// with 409 / ErrCodeHostnameAlreadyRouted, so an existing route is never something we can
	// simply create over: we either claim it in place or leave it alone and say why.
	var existing map[string]cloudflare.HostnameRoute
	if p.adoptUntagged && len(changes.Create) > 0 {
		idx, err := p.adoptionIndex(ctx)
		if err != nil {
			return err
		}
		existing = idx
	}

	skipped, err := p.applyCoreDNS(ctx, changes)
	if err != nil {
		return err
	}

	errs := skippedErrors(skipped)
	errs = append(errs, p.applyDeletes(ctx, changes.Delete, index)...)
	errs = append(errs, p.applyUpdates(ctx, changes.UpdateNew, index)...)
	errs = append(errs, p.applyCreates(ctx, changes.Create, existing, skipped)...)
	return errors.Join(errs...)
}

// applyDeletes deletes the routes the plan removes, returning one error per host that failed.
func (p *Provider) applyDeletes(ctx context.Context, deletes []*endpoint.Endpoint, index map[string]cloudflare.HostnameRoute) []error {
	var errs []error
	for _, ep := range deletes {
		if !p.domainFilter.Match(ep.DNSName) {
			continue
		}
		r, ok := index[strings.ToLower(ep.DNSName)]
		if !ok {
			continue // already gone, or not manageable by this instance
		}
		if p.dryRun {
			p.log.Info("dry run: would DELETE hostname route", "hostname", ep.DNSName, "route_id", r.ID)
			p.metrics.DryRunSkipped(metrics.OpDelete)
			continue
		}
		err := p.client.DeleteHostnameRoute(ctx, r.ID)
		p.metrics.APIRequest(metrics.OpDelete, err)
		if err != nil {
			errs = append(errs, fmt.Errorf("delete route %q: %w", ep.DNSName, err))
			continue
		}
		p.metrics.RouteDeleted()
	}
	return errs
}

// applyUpdates retargets the routes the plan moves to another tunnel, returning one error per host
// that failed. The route is PATCHed in place, so it keeps its id and the hostname never stops
// being routed. The old tunnel must still be listed (it is, while it drains), or Records would not
// have reported the route and no Update would have been planned.
//
// A PATCH that fails leaves the route on its old tunnel, so Records still reports the old target,
// the plan plans the same Update next cycle, and the retry is idempotent. An Update whose route is
// already on the wanted tunnel is a no-op, which covers a TTL- or label-only update.
//
// The full body (hostname, tunnel_id and comment) is sent, because that is the documented form;
// see cloudflare.PatchHostnameRoute for what has not yet been verified live.
func (p *Provider) applyUpdates(ctx context.Context, updates []*endpoint.Endpoint, index map[string]cloudflare.HostnameRoute) []error {
	var errs []error
	for _, ep := range updates {
		if !p.domainFilter.Match(ep.DNSName) {
			continue
		}
		want, ok := p.resolver.resolve(ep.DNSName)
		if !ok {
			errs = append(errs, fmt.Errorf("no tunnel configured for hostname %q", ep.DNSName))
			continue
		}
		r, ok := index[strings.ToLower(ep.DNSName)]
		if !ok {
			continue // not manageable by this instance, or already gone
		}
		if r.TunnelID == want {
			continue
		}
		if p.dryRun {
			p.log.Info("dry run: would RETARGET hostname route", "hostname", ep.DNSName,
				"route_id", r.ID, "from_tunnel_id", r.TunnelID, "to_tunnel_id", want)
			p.metrics.DryRunSkipped(metrics.OpRetarget)
			continue
		}
		_, err := p.client.PatchHostnameRoute(ctx, r.ID, cloudflare.RoutePatch{
			Hostname: r.Hostname, TunnelID: want, Comment: r.Comment,
		})
		p.metrics.APIRequest(metrics.OpRetarget, err)
		if err != nil {
			errs = append(errs, fmt.Errorf("retarget route %q to tunnel %s: %w", ep.DNSName, want, err))
			continue
		}
		p.metrics.RouteRetargeted()
		p.log.Info("retargeted hostname route", "hostname", ep.DNSName, "route_id", r.ID,
			"from_tunnel_id", r.TunnelID, "to_tunnel_id", want)
	}
	return errs
}

// applyCreates creates the routes the plan adds, returning one error per host that failed. A host
// in skipped already failed in applyCoreDNS and is left alone, so it gets neither a rewrite nor a
// route. A create refused as already-routed is recorded as pending, not returned.
func (p *Provider) applyCreates(ctx context.Context, creates []*endpoint.Endpoint,
	existing map[string]cloudflare.HostnameRoute, skipped map[string]error) []error {
	var errs []error

	// Naming the holder of a conflicting hostname needs an account-wide list. Do it lazily and at
	// most once per call, however many hostnames conflict.
	var accountRoutes map[string]cloudflare.HostnameRoute
	accountListed := false

	for _, ep := range creates {
		if !p.domainFilter.Match(ep.DNSName) {
			continue
		}
		host := strings.ToLower(ep.DNSName)
		if _, bad := skipped[host]; bad {
			continue
		}
		tid, ok := p.resolver.resolve(ep.DNSName)
		if !ok {
			errs = append(errs, fmt.Errorf("no tunnel configured for hostname %q", ep.DNSName))
			continue
		}
		if r, found := existing[host]; found {
			if err := p.adopt(ctx, r, tid); err != nil {
				errs = append(errs, err)
			}
			continue
		}
		if p.dryRun {
			p.log.Info("dry run: would CREATE hostname route",
				"hostname", ep.DNSName, "tunnel_id", tid, "comment", p.comment())
			p.metrics.DryRunSkipped(metrics.OpCreate)
			continue
		}
		_, err := p.client.CreateHostnameRoute(ctx, ep.DNSName, tid, p.comment())
		p.metrics.APIRequest(metrics.OpCreate, err)
		if err != nil {
			// Reachable even with adoption enabled: another writer can claim the hostname
			// between the list above and this create. Cloudflare's per-account uniqueness is the
			// mutex; losing it is a state to wait out, not a failure.
			if cloudflare.HasCode(err, cloudflare.ErrCodeHostnameAlreadyRouted) {
				if !accountListed {
					accountRoutes = p.accountRouteIndex(ctx)
					accountListed = true
				}
				r, found := accountRoutes[host]
				p.setPending(host, p.classifyConflict(ep.DNSName, tid, r, found))
				continue
			}
			errs = append(errs, fmt.Errorf("create route %q: %w", ep.DNSName, err))
			continue
		}
		p.clearPending(host)
		p.metrics.RouteCreated()
	}
	return errs
}

// classifyConflict explains why a create was refused as already-routed, logs what the operator
// can do about it, and returns the metrics reason. r is the live route holding the hostname when
// found. It is the only place the holder is named, and it names the holder's owner only at Debug:
// instances are expected to share an account, and who holds a name is not for another tenant's
// logs.
func (p *Provider) classifyConflict(host, wantTunnel string, r cloudflare.HostnameRoute, found bool) string {
	if !found {
		p.log.Info("hostname route not created: the hostname is already routed in Cloudflare, but no "+
			"live route was found for it (it may be mid-delete, or on a tunnel this token cannot see); "+
			"retrying every reconcile", "hostname", host, "tunnel_id", wantTunnel)
		return metrics.PendingUnknown
	}
	owner, managed := routeOwner(r.Comment)
	switch {
	case p.owns(r) && r.TunnelID == wantTunnel:
		p.log.Info("hostname route not created: this owner already routes it on the wanted tunnel "+
			"(a concurrent reconcile created it); the next Records() will see it",
			"hostname", host, "tunnel_id", wantTunnel, "route_id", r.ID)
		return metrics.PendingSelf
	case p.owns(r):
		p.log.Info("hostname route not created: THIS owner already routes it on a tunnel this "+
			"instance does not list, and nothing will release it; add that tunnel to TUNNEL_DRAIN "+
			"so it is listed and retargeted, or remove the route", "hostname", host, "wanted_tunnel_id", wantTunnel,
			"held_on_tunnel_id", r.TunnelID, "route_id", r.ID)
		return metrics.PendingSelf
	case managed:
		p.log.Info("hostname route not created: another external-dns owner holds the hostname; "+
			"it will be created once that owner releases it", "hostname", host, "tunnel_id", wantTunnel)
		p.log.Debug("conflicting route owner", "hostname", host, "owner", owner, "route_id", r.ID)
		return metrics.PendingOther
	default:
		if r.TunnelID == wantTunnel {
			p.log.Info("hostname route not created: a route with no owner tag already exists on the "+
				"wanted tunnel; set ADOPT_UNTAGGED=true to claim it in place",
				"hostname", host, "tunnel_id", wantTunnel, "route_id", r.ID)
		} else {
			p.log.Info("hostname route not created: a route with no owner tag holds the hostname on "+
				"another tunnel; it will be created once that route is removed",
				"hostname", host, "wanted_tunnel_id", wantTunnel, "held_on_tunnel_id", r.TunnelID)
		}
		return metrics.PendingUntagged
	}
}

// pending bookkeeping. A host is pending from the reconcile whose create was refused until there
// is evidence it is no longer waiting: it was created, it now appears in Records (so it exists and
// is ours), or it is no longer desired (its annotation was removed). The last two are what stop
// the gauge sticking at its old value when ExternalDNS plans nothing and never calls ApplyChanges
// again for that host.

func (p *Provider) setPending(host, reason string) {
	p.pendingMu.Lock()
	defer p.pendingMu.Unlock()
	p.pending[host] = reason
	p.publishPendingLocked()
}

func (p *Provider) clearPending(host string) {
	p.pendingMu.Lock()
	defer p.pendingMu.Unlock()
	if _, ok := p.pending[host]; !ok {
		return
	}
	delete(p.pending, host)
	p.publishPendingLocked()
}

// retainPending drops every pending host for which keep returns false.
func (p *Provider) retainPending(keep func(host string) bool) {
	p.pendingMu.Lock()
	defer p.pendingMu.Unlock()
	changed := false
	for host := range p.pending {
		if !keep(host) {
			delete(p.pending, host)
			changed = true
		}
	}
	if changed {
		p.publishPendingLocked()
	}
}

func (p *Provider) publishPendingLocked() {
	counts := map[string]int{}
	for _, reason := range p.pending {
		counts[reason]++
	}
	p.metrics.SetRoutesPending(counts)
}

// ownedRouteIndex lists every configured tunnel and returns the live routes this instance may
// delete, keyed by lowercase hostname (see manageable for what is eligible). The value is the
// whole route, not just its id, so callers can also see which tunnel it is on.
func (p *Provider) ownedRouteIndex(ctx context.Context) (map[string]cloudflare.HostnameRoute, error) {
	index := map[string]cloudflare.HostnameRoute{}
	for _, tid := range p.resolver.tunnels() {
		routes, err := p.client.ListHostnameRoutes(ctx, tid)
		p.metrics.APIRequest(metrics.OpList, err)
		if err != nil {
			p.metrics.ListError(tid)
			return nil, fmt.Errorf("list routes for delete: %w", err)
		}
		for _, r := range routes {
			if r.DeletedAt != nil {
				continue
			}
			if !p.manageable(r) {
				continue
			}
			index[strings.ToLower(r.Hostname)] = r
		}
	}
	return index, nil
}

// adoptionIndex lists every configured tunnel and returns ALL live routes on them, whoever owns
// them, keyed by lowercase hostname. adopt needs to see routes it must refuse.
func (p *Provider) adoptionIndex(ctx context.Context) (map[string]cloudflare.HostnameRoute, error) {
	index := map[string]cloudflare.HostnameRoute{}
	for _, tid := range p.resolver.tunnels() {
		routes, err := p.client.ListHostnameRoutes(ctx, tid)
		p.metrics.APIRequest(metrics.OpList, err)
		if err != nil {
			p.metrics.ListError(tid)
			return nil, fmt.Errorf("list routes for adoption: %w", err)
		}
		for _, r := range routes {
			if r.DeletedAt != nil {
				continue
			}
			index[strings.ToLower(r.Hostname)] = r
		}
	}
	return index, nil
}

// accountRouteIndex lists every live route the token can see in the account, keyed by lowercase
// hostname. It exists only to name the holder of a conflicting hostname, so a failure is logged
// and yields an empty index instead of an error: being unable to explain a conflict must never
// turn a pending host into a failed batch. Under a token scoped to this instance's tunnels the
// list simply omits other tunnels' routes, which classifyConflict reports as unknown.
func (p *Provider) accountRouteIndex(ctx context.Context) map[string]cloudflare.HostnameRoute {
	index := map[string]cloudflare.HostnameRoute{}
	routes, err := p.client.ListHostnameRoutes(ctx, "")
	p.metrics.APIRequest(metrics.OpList, err)
	if err != nil {
		p.metrics.ListError("account")
		p.log.Debug("could not list the account's routes to classify a conflict", "err", err)
		return index
	}
	for _, r := range routes {
		if r.DeletedAt != nil {
			continue
		}
		index[strings.ToLower(r.Hostname)] = r
	}
	return index
}

// skippedErrors returns the per-host errors from applyCoreDNS in hostname order, so the joined
// error text is deterministic.
func skippedErrors(skipped map[string]error) []error {
	hosts := make([]string, 0, len(skipped))
	for host := range skipped {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	errs := make([]error, 0, len(hosts))
	for _, host := range hosts {
		errs = append(errs, skipped[host])
	}
	return errs
}

// applyCoreDNS writes the in-cluster leg for this plan, in ONE server-side apply, BEFORE any
// Cloudflare mutation. A nil fragment writer makes it a no-op.
//
// The ordering is load-bearing, not stylistic. ExternalDNS computes its plan from Records(), which
// reads Cloudflare — so Cloudflare is the plan's source of truth. If Cloudflare were mutated first
// and the fragment write then failed, the next reconcile would see the route already present, plan
// no further Create, and the CoreDNS answer would never appear: the hostname would stay
// unresolvable with nothing left to retry it. Writing Cloudflare LAST means any failure leaves the
// plan able to re-issue the whole change, and Fragment.Apply is idempotent, so retries converge.
// The same argument runs in reverse for deletes, which is why both legs of both directions are
// handled here rather than interleaved with the Cloudflare loops.
//
// Both orderings leave a brief window where a hostname has one leg and not the other; that window
// is unavoidable (a route without an answer and an answer without a route both fail to resolve).
// Only convergence-after-failure distinguishes them.
//
// A host that cannot be answered (no resource label, a resource that is not a Service, a wildcard
// name that an exact rewrite cannot match) is returned in skipped and gets no rewrite; the caller
// must also not create its route. The other hosts in the batch are still written. The error
// return is reserved for the fragment write itself failing, which aborts the whole batch.
func (p *Provider) applyCoreDNS(ctx context.Context, changes *plan.Changes) (map[string]error, error) {
	if p.coredns == nil {
		return nil, nil
	}

	skipped := map[string]error{}
	add := map[string]string{}
	for _, ep := range changes.Create {
		if !p.domainFilter.Match(ep.DNSName) {
			continue
		}
		host := strings.ToLower(ep.DNSName)
		if strings.Contains(host, "*") {
			skipped[host] = fmt.Errorf("cannot write the CoreDNS answer for wildcard hostname %q: "+
				"a CoreDNS \"rewrite name exact\" rule cannot match a wildcard", ep.DNSName)
			continue
		}
		resource := ep.Labels[endpoint.ResourceLabelKey]
		if resource == "" {
			skipped[host] = fmt.Errorf("cannot write the CoreDNS answer for %q: the endpoint carries no %q "+
				"label, so the backing Service is unknown (ExternalDNS sets it for --source=service)",
				ep.DNSName, endpoint.ResourceLabelKey)
			continue
		}
		target, terr := p.coredns.ServiceTarget(resource)
		if terr != nil {
			skipped[host] = fmt.Errorf("CoreDNS answer for %q: %w", ep.DNSName, terr)
			continue
		}
		add[host] = target
	}

	// Deletes are listed unconditionally rather than filtered by ownership: we only ever ADD
	// rewrites for hostnames we manage, so removing one we never added is a no-op inside Apply.
	var remove []string
	for _, ep := range changes.Delete {
		if !p.domainFilter.Match(ep.DNSName) {
			continue
		}
		remove = append(remove, strings.ToLower(ep.DNSName))
	}

	if len(add) == 0 && len(remove) == 0 {
		return skipped, nil
	}
	if p.dryRun {
		p.log.Info("dry run: would UPDATE the CoreDNS fragment",
			"key", p.coredns.Key(), "add", add, "remove", remove)
		p.metrics.DryRunSkipped(metrics.OpFragment)
		return skipped, nil
	}

	after, aerr := p.coredns.Apply(ctx, add, remove)
	p.metrics.CoreDNSWrite(aerr)
	if aerr != nil {
		return nil, fmt.Errorf("update CoreDNS fragment %q: %w", p.coredns.Key(), aerr)
	}
	p.metrics.SetCoreDNSRewrites(len(after))
	p.log.Info("updated CoreDNS fragment", "key", p.coredns.Key(),
		"added", len(add), "removed", len(remove), "rewrites", len(after))
	return skipped, nil
}

// reconcileExistingCoreDNS applies desired Service targets only for hostnames already exposed
// by Records in this reconciliation. This closes the otherwise invisible replacement case:
// the Cloudflare route's canonical CNAME is unchanged, so ExternalDNS has no ApplyChanges call,
// but the Service resource label (and therefore the CoreDNS target) has changed.
//
// It intentionally does not remove names absent from desired endpoints. Deletion remains driven
// by ExternalDNS's policy-filtered plan in ApplyChanges, preserving sync/upsert-only semantics
// and avoiding a CoreDNS-only delete when the caller has disabled route deletion.
//
// A wildcard name is skipped with a warning rather than failing the call: an existing wildcard
// route must not stop every reconciliation just because CoreDNS was enabled later, and a rewrite
// could never have answered it anyway.
func (p *Provider) reconcileExistingCoreDNS(ctx context.Context, desired []*endpoint.Endpoint) error {
	if p.coredns == nil {
		return nil
	}
	existing := p.recordHosts()
	if len(existing) == 0 {
		return nil
	}

	changes := &plan.Changes{}
	for _, ep := range desired {
		host := strings.ToLower(ep.DNSName)
		if _, ok := existing[host]; !ok {
			continue
		}
		if strings.Contains(host, "*") {
			p.log.Warn("not reconciling the CoreDNS answer for an existing wildcard route: "+
				"an exact rewrite cannot match a wildcard", "hostname", ep.DNSName)
			continue
		}
		changes.Create = append(changes.Create, ep)
	}
	if len(changes.Create) == 0 {
		return nil
	}
	skipped, err := p.applyCoreDNS(ctx, changes)
	if err != nil {
		return err
	}
	return errors.Join(skippedErrors(skipped)...)
}

// adopt claims a pre-existing route for this owner by rewriting only its comment, leaving the
// route id and the hostname->tunnel binding untouched — so the hostname never stops resolving.
// This is what turns a Terraform->annotations migration from "delete and recreate" (an NXDOMAIN
// window per host) into a metadata rewrite.
//
// It refuses, with a descriptive error, whenever the route is not safely claimable. Refusing
// loudly is the right default: the alternative is silently taking over a route another system
// believes it owns.
func (p *Provider) adopt(ctx context.Context, r cloudflare.HostnameRoute, wantTunnel string) error {
	if r.TunnelID != wantTunnel {
		return fmt.Errorf("refusing to adopt route %q (id %s): it is bound to tunnel %s but this "+
			"hostname resolves to tunnel %s; retarget or remove the existing route first",
			r.Hostname, r.ID, r.TunnelID, wantTunnel)
	}
	owner, managed := routeOwner(r.Comment)
	switch {
	case managed && owner == p.ownerID:
		// Already ours. Reachable when the route is outside what Records() reports (e.g. it sits
		// on a tunnel this instance resolves but did not list). Nothing to claim.
		return nil
	case managed:
		return fmt.Errorf("refusing to adopt route %q (id %s): it is already managed by "+
			"external-dns owner %q", r.Hostname, r.ID, owner)
	}
	if p.dryRun {
		p.log.Info("dry run: would ADOPT existing hostname route",
			"hostname", r.Hostname, "route_id", r.ID, "tunnel_id", r.TunnelID,
			"old_comment", r.Comment, "new_comment", p.comment())
		p.metrics.DryRunSkipped(metrics.OpPatch)
		return nil
	}
	if _, err := p.client.PatchHostnameRouteComment(ctx, r.ID, p.comment()); err != nil {
		p.metrics.APIRequest(metrics.OpPatch, err)
		return fmt.Errorf("adopt route %q (id %s): %w", r.Hostname, r.ID, err)
	}
	p.metrics.APIRequest(metrics.OpPatch, nil)
	// Info, not Debug: this is a durable ownership transfer, and the overwritten comment is the
	// only record of what previously claimed the route.
	p.log.Info("adopted existing hostname route",
		"hostname", r.Hostname, "route_id", r.ID, "tunnel_id", r.TunnelID,
		"old_comment", r.Comment, "new_comment", p.comment())
	p.metrics.RouteAdopted()
	return nil
}
