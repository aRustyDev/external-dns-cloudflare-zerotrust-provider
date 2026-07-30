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
// This provider owns ONLY the Cloudflare route half of a `.private` name. The in-cluster
// CoreDNS answer (name -> Service ClusterIP) is a separate concern (a CoreDNS fragment / etcd
// source) and is intentionally out of scope here.
//
// Ownership: routes are tagged with a "managed-by=external-dns/<owner>" comment. In
// ownership-strict mode the provider only ever reads back and deletes routes carrying its own
// owner tag, so it cannot disturb routes created by Terraform or by hand — important where an
// external system (e.g. Terraform) is the declared sole owner of some `.private` routes.
//
// Dry run: ExternalDNS's own --dry-run flag is silently INERT for webhook providers (see
// docs/upstream-dry-run-gap.md), so this provider implements its own DryRun, which is the only
// thing that actually protects a live Cloudflare account.
package provider

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"
	extprovider "sigs.k8s.io/external-dns/provider"

	"github.com/arustydev/external-dns-cloudflare-zerotrust-provider/internal/cloudflare"
	"github.com/arustydev/external-dns-cloudflare-zerotrust-provider/internal/metrics"
)

// recordType is the type we synthesize for every managed hostname route.
const recordType = endpoint.RecordTypeCNAME

// managedByPrefix is the comment prefix stamped on every route this project creates.
const managedByPrefix = "managed-by=external-dns"

// routeAPI is the subset of the Cloudflare client the provider needs (interface for testability).
type routeAPI interface {
	ListHostnameRoutes(ctx context.Context, tunnelID string) ([]cloudflare.HostnameRoute, error)
	CreateHostnameRoute(ctx context.Context, hostname, tunnelID, comment string) (*cloudflare.HostnameRoute, error)
	PatchHostnameRouteComment(ctx context.Context, id, comment string) (*cloudflare.HostnameRoute, error)
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
	domainFilter    *endpoint.DomainFilter
	metrics         *metrics.Metrics
	log             *slog.Logger
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
	DomainFilter  []string
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
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	// Publish the gauge at construction so it reads correctly from the first scrape, not just
	// after the first reconcile.
	cfg.Metrics.SetDryRun(cfg.DryRun)
	return &Provider{
		BaseProvider:    &extprovider.BaseProvider{},
		client:          cfg.Client,
		resolver:        resolver,
		ownerID:         cfg.OwnerID,
		ownershipStrict: cfg.OwnershipStrict,
		dryRun:          cfg.DryRun,
		adoptUntagged:   cfg.AdoptUntagged,
		domainFilter:    endpoint.NewDomainFilter(cfg.DomainFilter),
		metrics:         cfg.Metrics,
		log:             logger,
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

// owns reports whether this provider instance owns the route (managed by us, our owner id).
func (p *Provider) owns(r cloudflare.HostnameRoute) bool {
	owner, managed := routeOwner(r.Comment)
	return managed && owner == p.ownerID
}

// Records lists managed hostname routes across the configured tunnel(s) as CNAME endpoints.
// It filters by domain filter and, in ownership-strict mode, by owner tag.
func (p *Provider) Records(ctx context.Context) ([]*endpoint.Endpoint, error) {
	var out []*endpoint.Endpoint
	for _, tid := range p.resolver.tunnels() {
		routes, err := p.client.ListHostnameRoutes(ctx, tid)
		p.metrics.APIRequest(metrics.OpList, err)
		if err != nil {
			return nil, err
		}
		target := p.resolver.target(tid)
		for _, r := range routes {
			if r.DeletedAt != nil {
				continue
			}
			if !p.domainFilter.Match(r.Hostname) {
				continue
			}
			if p.ownershipStrict && !p.owns(r) {
				continue
			}
			out = append(out, endpoint.NewEndpoint(r.Hostname, recordType, target))
		}
	}
	p.metrics.SetRecordsManaged(len(out))
	return out, nil
}

// AdjustEndpoints canonicalizes candidate endpoints so plan diffs are stable: everything we
// manage becomes a CNAME to the target of the tunnel selected for its hostname. Hostnames
// outside the domain filter, or with no matching tunnel, are dropped.
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
		out = append(out, endpoint.NewEndpoint(ep.DNSName, recordType, target))
	}
	return out, nil
}

// GetDomainFilter exposes the configured domain filter to ExternalDNS.
func (p *Provider) GetDomainFilter() endpoint.DomainFilterInterface {
	return p.domainFilter
}

// ApplyChanges creates/deletes hostname routes to satisfy the plan. Updates are no-ops: a
// route is just a hostname->tunnel binding with no mutable attributes this provider manages.
//
// With AdoptUntagged enabled, a create whose hostname already has a route CLAIMS that route
// (comment PATCH) rather than failing — see adopt.
//
// In dry-run mode the gate sits at each mutating call rather than at the top of the function.
// That is deliberate: the domain filter, tunnel resolution, ownership filtering and the
// hostname->route-id lookup all still run, so the logged plan reflects what would really happen
// and misconfiguration (e.g. a hostname with no configured tunnel) still fails loudly.
func (p *Provider) ApplyChanges(ctx context.Context, changes *plan.Changes) error {
	if changes == nil || (len(changes.Create) == 0 && len(changes.Delete) == 0) {
		return nil
	}
	start := time.Now()
	defer func() { p.metrics.ObserveApply(time.Since(start).Seconds()) }()

	// Build hostname -> route-id from the live set once, for deletes. In ownership-strict mode
	// only our own routes are eligible, so we never delete Terraform-owned / hand-created ones.
	byHost := map[string]string{}
	if len(changes.Delete) > 0 {
		for _, tid := range p.resolver.tunnels() {
			routes, err := p.client.ListHostnameRoutes(ctx, tid)
			p.metrics.APIRequest(metrics.OpList, err)
			if err != nil {
				return fmt.Errorf("list routes for delete: %w", err)
			}
			for _, r := range routes {
				if r.DeletedAt != nil {
					continue
				}
				if p.ownershipStrict && !p.owns(r) {
					continue
				}
				byHost[strings.ToLower(r.Hostname)] = r.ID
			}
		}
	}

	// Adoption must see routes this instance does NOT own, so this index is built WITHOUT the
	// ownership filter (unlike the delete index above). Cloudflare rejects a duplicate hostname
	// with 409 / ErrCodeHostnameAlreadyRouted, so an existing route is never something we can
	// simply create over: we either claim it in place or leave it alone and say why.
	var existing map[string]cloudflare.HostnameRoute
	if p.adoptUntagged && len(changes.Create) > 0 {
		existing = map[string]cloudflare.HostnameRoute{}
		for _, tid := range p.resolver.tunnels() {
			routes, err := p.client.ListHostnameRoutes(ctx, tid)
			p.metrics.APIRequest(metrics.OpList, err)
			if err != nil {
				return fmt.Errorf("list routes for adoption: %w", err)
			}
			for _, r := range routes {
				if r.DeletedAt != nil {
					continue
				}
				existing[strings.ToLower(r.Hostname)] = r
			}
		}
	}

	for _, ep := range changes.Create {
		if !p.domainFilter.Match(ep.DNSName) {
			continue
		}
		tid, ok := p.resolver.resolve(ep.DNSName)
		if !ok {
			return fmt.Errorf("no tunnel configured for hostname %q", ep.DNSName)
		}
		if r, found := existing[strings.ToLower(ep.DNSName)]; found {
			if err := p.adopt(ctx, r, tid); err != nil {
				return err
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
			// between the list above and this create.
			if cloudflare.HasCode(err, cloudflare.ErrCodeHostnameAlreadyRouted) {
				return fmt.Errorf("create route %q: hostname is already routed in Cloudflare "+
					"(error %d — note its message says \"another tunnel\" even when the existing "+
					"route is on the SAME tunnel). Set ADOPT_UNTAGGED=true to claim the existing "+
					"route in place instead of recreating it: %w",
					ep.DNSName, cloudflare.ErrCodeHostnameAlreadyRouted, err)
			}
			return fmt.Errorf("create route %q: %w", ep.DNSName, err)
		}
		p.metrics.RouteCreated()
	}

	for _, ep := range changes.Delete {
		if !p.domainFilter.Match(ep.DNSName) {
			continue
		}
		id, ok := byHost[strings.ToLower(ep.DNSName)]
		if !ok {
			continue // already gone, or not owned by us in strict mode
		}
		if p.dryRun {
			p.log.Info("dry run: would DELETE hostname route", "hostname", ep.DNSName, "route_id", id)
			p.metrics.DryRunSkipped(metrics.OpDelete)
			continue
		}
		err := p.client.DeleteHostnameRoute(ctx, id)
		p.metrics.APIRequest(metrics.OpDelete, err)
		if err != nil {
			return fmt.Errorf("delete route %q: %w", ep.DNSName, err)
		}
		p.metrics.RouteDeleted()
	}
	return nil
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
