package provider

import (
	"context"
	"testing"

	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"

	"github.com/arustydev/external-dns-cloudflare-zerotrust-provider/internal/cloudflare"
)

const testTunnel = "f70ff985-a4ef-4643-bbbc-4a0ed4fc8415"

// fakeAPI is an in-memory routeAPI.
type fakeAPI struct {
	routes  []cloudflare.HostnameRoute
	created []string
	deleted []string
	nextID  int
}

func (f *fakeAPI) ListHostnameRoutes(_ context.Context, _ string) ([]cloudflare.HostnameRoute, error) {
	return f.routes, nil
}

func (f *fakeAPI) CreateHostnameRoute(_ context.Context, hostname, tunnelID, _ string) (*cloudflare.HostnameRoute, error) {
	f.nextID++
	r := cloudflare.HostnameRoute{ID: "id-" + hostname, Hostname: hostname, TunnelID: tunnelID}
	f.routes = append(f.routes, r)
	f.created = append(f.created, hostname)
	return &r, nil
}

func (f *fakeAPI) DeleteHostnameRoute(_ context.Context, id string) error {
	f.deleted = append(f.deleted, id)
	return nil
}

func newTestProvider(t *testing.T, api routeAPI, domains ...string) *Provider {
	t.Helper()
	p, err := New(Config{Client: api, TunnelID: testTunnel, OwnerID: "test", DomainFilter: domains})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

func TestRecords_FiltersAndMaps(t *testing.T) {
	api := &fakeAPI{routes: []cloudflare.HostnameRoute{
		{ID: "1", Hostname: "foo.woven", TunnelID: testTunnel},
		{ID: "2", Hostname: "bar.example.com", TunnelID: testTunnel}, // out of domain filter
	}}
	p := newTestProvider(t, api, "woven")

	eps, err := p.Records(context.Background())
	if err != nil {
		t.Fatalf("Records: %v", err)
	}
	if len(eps) != 1 {
		t.Fatalf("want 1 endpoint, got %d", len(eps))
	}
	if eps[0].DNSName != "foo.woven" || eps[0].RecordType != endpoint.RecordTypeCNAME {
		t.Fatalf("unexpected endpoint: %+v", eps[0])
	}
	if got := eps[0].Targets[0]; got != testTunnel+".cfargotunnel.com" {
		t.Fatalf("target = %q, want tunnel target", got)
	}
}

func TestAdjustEndpoints_Canonicalizes(t *testing.T) {
	p := newTestProvider(t, &fakeAPI{}, "woven")
	in := []*endpoint.Endpoint{
		endpoint.NewEndpoint("foo.woven", endpoint.RecordTypeA, "10.0.0.5"), // wrong type+target
		endpoint.NewEndpoint("skip.example.com", endpoint.RecordTypeA, "1.2.3.4"),
	}
	out, err := p.AdjustEndpoints(in)
	if err != nil {
		t.Fatalf("AdjustEndpoints: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("want 1 (domain-filtered), got %d", len(out))
	}
	if out[0].RecordType != endpoint.RecordTypeCNAME || out[0].Targets[0] != testTunnel+".cfargotunnel.com" {
		t.Fatalf("not canonicalized: %+v", out[0])
	}
}

func TestApplyChanges_CreateAndDelete(t *testing.T) {
	api := &fakeAPI{routes: []cloudflare.HostnameRoute{
		{ID: "id-old.woven", Hostname: "old.woven", TunnelID: testTunnel},
	}}
	p := newTestProvider(t, api, "woven")

	changes := &plan.Changes{
		Create: []*endpoint.Endpoint{endpoint.NewEndpoint("new.woven", endpoint.RecordTypeCNAME, p.tunnelTarget)},
		Delete: []*endpoint.Endpoint{endpoint.NewEndpoint("old.woven", endpoint.RecordTypeCNAME, p.tunnelTarget)},
	}
	if err := p.ApplyChanges(context.Background(), changes); err != nil {
		t.Fatalf("ApplyChanges: %v", err)
	}
	if len(api.created) != 1 || api.created[0] != "new.woven" {
		t.Fatalf("created = %v, want [new.woven]", api.created)
	}
	if len(api.deleted) != 1 || api.deleted[0] != "id-old.woven" {
		t.Fatalf("deleted = %v, want [id-old.woven]", api.deleted)
	}
}

func TestApplyChanges_NilIsNoop(t *testing.T) {
	api := &fakeAPI{}
	p := newTestProvider(t, api, "woven")
	if err := p.ApplyChanges(context.Background(), nil); err != nil {
		t.Fatalf("nil changes should be a no-op, got %v", err)
	}
}
