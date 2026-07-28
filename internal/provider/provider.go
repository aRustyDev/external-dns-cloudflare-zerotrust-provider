// Package provider implements the ExternalDNS provider.Provider interface backed by
// Cloudflare Zero Trust private hostname routes.
//
// Mapping model: a Cloudflare Tunnel has the canonical target "<tunnel-id>.cfargotunnel.com".
// We represent every managed hostname as a CNAME Endpoint pointing at that target, so
// ExternalDNS's plan produces stable diffs. ApplyChanges then translates Create/Delete into
// Zero Trust hostname-route CRUD on the configured tunnel.
//
// This provider owns ONLY the Cloudflare route half of a private `.woven` name. The in-cluster
// CoreDNS answer (name -> Service ClusterIP) is a separate concern (a CoreDNS fragment / etcd
// source) and is intentionally out of scope here.
package provider

import (
	"context"
	"fmt"
	"strings"

	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"
	extprovider "sigs.k8s.io/external-dns/provider"

	"github.com/arustydev/external-dns-cloudflare-zerotrust-provider/internal/cloudflare"
)

// recordType is the type we synthesize for every managed hostname route.
const recordType = endpoint.RecordTypeCNAME

// routeAPI is the subset of the Cloudflare client the provider needs (interface for testability).
type routeAPI interface {
	ListHostnameRoutes(ctx context.Context, tunnelID string) ([]cloudflare.HostnameRoute, error)
	CreateHostnameRoute(ctx context.Context, hostname, tunnelID, comment string) (*cloudflare.HostnameRoute, error)
	DeleteHostnameRoute(ctx context.Context, id string) error
}

// Provider is the ExternalDNS provider for Cloudflare Zero Trust hostname routes.
type Provider struct {
	*extprovider.BaseProvider

	client       routeAPI
	tunnelID     string
	tunnelTarget string // "<tunnel-id>.cfargotunnel.com"
	ownerID      string
	domainFilter *endpoint.DomainFilter
}

// Config configures a Provider.
type Config struct {
	Client       routeAPI
	TunnelID     string
	OwnerID      string
	DomainFilter []string
}

// New builds a Provider.
func New(cfg Config) (*Provider, error) {
	if cfg.Client == nil {
		return nil, fmt.Errorf("cloudflare client is required")
	}
	if cfg.TunnelID == "" {
		return nil, fmt.Errorf("tunnel id is required")
	}
	df := endpoint.NewDomainFilter(cfg.DomainFilter)
	return &Provider{
		BaseProvider: &extprovider.BaseProvider{},
		client:       cfg.Client,
		tunnelID:     cfg.TunnelID,
		tunnelTarget: cfg.TunnelID + ".cfargotunnel.com",
		ownerID:      cfg.OwnerID,
		domainFilter: df,
	}, nil
}

// comment tags routes we manage so they are distinguishable from hand-created ones.
func (p *Provider) comment() string {
	if p.ownerID == "" {
		return "managed-by=external-dns"
	}
	return "managed-by=external-dns/" + p.ownerID
}

// Records lists the tunnel's hostname routes as CNAME endpoints (filtered by domain filter).
func (p *Provider) Records(ctx context.Context) ([]*endpoint.Endpoint, error) {
	routes, err := p.client.ListHostnameRoutes(ctx, p.tunnelID)
	if err != nil {
		return nil, err
	}
	var out []*endpoint.Endpoint
	for _, r := range routes {
		if r.DeletedAt != nil {
			continue
		}
		if !p.domainFilter.Match(r.Hostname) {
			continue
		}
		out = append(out, endpoint.NewEndpoint(r.Hostname, recordType, p.tunnelTarget))
	}
	return out, nil
}

// AdjustEndpoints canonicalizes candidate endpoints so plan diffs are stable: everything we
// manage is a CNAME to the tunnel target, regardless of what the source proposed.
func (p *Provider) AdjustEndpoints(endpoints []*endpoint.Endpoint) ([]*endpoint.Endpoint, error) {
	var out []*endpoint.Endpoint
	for _, ep := range endpoints {
		if !p.domainFilter.Match(ep.DNSName) {
			continue
		}
		out = append(out, endpoint.NewEndpoint(ep.DNSName, recordType, p.tunnelTarget))
	}
	return out, nil
}

// GetDomainFilter exposes the configured domain filter to ExternalDNS.
func (p *Provider) GetDomainFilter() endpoint.DomainFilterInterface {
	return p.domainFilter
}

// ApplyChanges creates/deletes hostname routes to satisfy the plan. Updates are no-ops: a
// route is just a hostname->tunnel binding, and this provider serves a single tunnel.
func (p *Provider) ApplyChanges(ctx context.Context, changes *plan.Changes) error {
	if changes == nil || (len(changes.Create) == 0 && len(changes.Delete) == 0) {
		return nil
	}

	// Build hostname -> route-id from the live set once, for deletes.
	byHost := map[string]string{}
	if len(changes.Delete) > 0 {
		routes, err := p.client.ListHostnameRoutes(ctx, p.tunnelID)
		if err != nil {
			return fmt.Errorf("list routes for delete: %w", err)
		}
		for _, r := range routes {
			if r.DeletedAt == nil {
				byHost[strings.ToLower(r.Hostname)] = r.ID
			}
		}
	}

	for _, ep := range changes.Create {
		if !p.domainFilter.Match(ep.DNSName) {
			continue
		}
		if _, err := p.client.CreateHostnameRoute(ctx, ep.DNSName, p.tunnelID, p.comment()); err != nil {
			return fmt.Errorf("create route %q: %w", ep.DNSName, err)
		}
	}

	for _, ep := range changes.Delete {
		if !p.domainFilter.Match(ep.DNSName) {
			continue
		}
		id, ok := byHost[strings.ToLower(ep.DNSName)]
		if !ok {
			continue // already gone
		}
		if err := p.client.DeleteHostnameRoute(ctx, id); err != nil {
			return fmt.Errorf("delete route %q: %w", ep.DNSName, err)
		}
	}
	return nil
}
