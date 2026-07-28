package provider

import (
	"context"
	"testing"

	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"

	"github.com/arustydev/external-dns-cloudflare-zerotrust-provider/internal/cloudflare"
)

const testTunnel = "f70ff985-a4ef-4643-bbbc-4a0ed4fc8415"

// fakeAPI is an in-memory routeAPI. ListHostnameRoutes filters by tunnel id (blank = all),
// mirroring the real API's tunnel_id query param, and CreateHostnameRoute records the comment
// and tunnel it was called with so tests can assert ownership tagging and tunnel selection.
type fakeAPI struct {
	routes         []cloudflare.HostnameRoute
	created        []string
	createdTunnels []string
	deleted        []string
	nextID         int
}

func (f *fakeAPI) ListHostnameRoutes(_ context.Context, tunnelID string) ([]cloudflare.HostnameRoute, error) {
	if tunnelID == "" {
		return f.routes, nil
	}
	var out []cloudflare.HostnameRoute
	for _, r := range f.routes {
		if r.TunnelID == tunnelID {
			out = append(out, r)
		}
	}
	return out, nil
}

func (f *fakeAPI) CreateHostnameRoute(_ context.Context, hostname, tunnelID, comment string) (*cloudflare.HostnameRoute, error) {
	f.nextID++
	r := cloudflare.HostnameRoute{ID: "id-" + hostname, Hostname: hostname, TunnelID: tunnelID, Comment: comment}
	f.routes = append(f.routes, r)
	f.created = append(f.created, hostname)
	f.createdTunnels = append(f.createdTunnels, tunnelID)
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

	target := p.resolver.target(testTunnel)
	changes := &plan.Changes{
		Create: []*endpoint.Endpoint{endpoint.NewEndpoint("new.woven", endpoint.RecordTypeCNAME, target)},
		Delete: []*endpoint.Endpoint{endpoint.NewEndpoint("old.woven", endpoint.RecordTypeCNAME, target)},
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

// strictProvider builds a provider in ownership-strict mode with the given owner.
func strictProvider(t *testing.T, api routeAPI, owner string, domains ...string) *Provider {
	t.Helper()
	p, err := New(Config{Client: api, TunnelID: testTunnel, OwnerID: owner, OwnershipStrict: true, DomainFilter: domains})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

func TestOwnershipStrict_RecordsOnlyOwned(t *testing.T) {
	api := &fakeAPI{routes: []cloudflare.HostnameRoute{
		{ID: "1", Hostname: "mine.woven", TunnelID: testTunnel, Comment: "managed-by=external-dns/test"},
		{ID: "2", Hostname: "theirs.woven", TunnelID: testTunnel, Comment: "managed-by=external-dns/other"},
		{ID: "3", Hostname: "manual.woven", TunnelID: testTunnel, Comment: "hand-created"},
	}}

	// Strict: only our own route surfaces.
	strict := strictProvider(t, api, "test", "woven")
	eps, err := strict.Records(context.Background())
	if err != nil {
		t.Fatalf("Records: %v", err)
	}
	if len(eps) != 1 || eps[0].DNSName != "mine.woven" {
		t.Fatalf("strict Records = %v, want [mine.woven]", names(eps))
	}

	// Non-strict: all domain-matching routes surface, regardless of owner.
	loose := newTestProvider(t, api, "woven")
	eps, err = loose.Records(context.Background())
	if err != nil {
		t.Fatalf("Records: %v", err)
	}
	if len(eps) != 3 {
		t.Fatalf("non-strict Records = %v, want all 3", names(eps))
	}
}

func TestOwnershipStrict_DeleteSkipsUnowned(t *testing.T) {
	api := &fakeAPI{routes: []cloudflare.HostnameRoute{
		{ID: "id-mine.woven", Hostname: "mine.woven", TunnelID: testTunnel, Comment: "managed-by=external-dns/test"},
		{ID: "id-manual.woven", Hostname: "manual.woven", TunnelID: testTunnel, Comment: "hand-created"},
	}}
	p := strictProvider(t, api, "test", "woven")

	// Ask to delete both; only the owned one may actually be deleted.
	changes := &plan.Changes{Delete: []*endpoint.Endpoint{
		endpoint.NewEndpoint("mine.woven", endpoint.RecordTypeCNAME, p.resolver.target(testTunnel)),
		endpoint.NewEndpoint("manual.woven", endpoint.RecordTypeCNAME, p.resolver.target(testTunnel)),
	}}
	if err := p.ApplyChanges(context.Background(), changes); err != nil {
		t.Fatalf("ApplyChanges: %v", err)
	}
	if len(api.deleted) != 1 || api.deleted[0] != "id-mine.woven" {
		t.Fatalf("deleted = %v, want only [id-mine.woven] (never the hand-created route)", api.deleted)
	}
}

func TestMultiTunnel_CreateRoutesToMostSpecificTunnel(t *testing.T) {
	const t1, t2 = "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"
	api := &fakeAPI{}
	p, err := New(Config{
		Client:       api,
		TunnelMap:    map[string]string{"woven": t1, "apps.woven": t2},
		OwnerID:      "test",
		DomainFilter: []string{"woven"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	changes := &plan.Changes{Create: []*endpoint.Endpoint{
		endpoint.NewEndpoint("svc.apps.woven", endpoint.RecordTypeCNAME, ""), // -> apps.woven tunnel (t2)
		endpoint.NewEndpoint("bare.woven", endpoint.RecordTypeCNAME, ""),     // -> woven tunnel (t1)
	}}
	if err := p.ApplyChanges(context.Background(), changes); err != nil {
		t.Fatalf("ApplyChanges: %v", err)
	}

	got := map[string]string{}
	for i, h := range api.created {
		got[h] = api.createdTunnels[i]
	}
	if got["svc.apps.woven"] != t2 {
		t.Errorf("svc.apps.woven bound to %q, want most-specific tunnel %q", got["svc.apps.woven"], t2)
	}
	if got["bare.woven"] != t1 {
		t.Errorf("bare.woven bound to %q, want %q", got["bare.woven"], t1)
	}
}

func TestMultiTunnel_RecordsUsesPerTunnelTarget(t *testing.T) {
	const t1, t2 = "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"
	api := &fakeAPI{routes: []cloudflare.HostnameRoute{
		{ID: "1", Hostname: "bare.woven", TunnelID: t1},
		{ID: "2", Hostname: "svc.apps.woven", TunnelID: t2},
	}}
	p, err := New(Config{
		Client:       api,
		TunnelMap:    map[string]string{"woven": t1, "apps.woven": t2},
		DomainFilter: []string{"woven"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	eps, err := p.Records(context.Background())
	if err != nil {
		t.Fatalf("Records: %v", err)
	}
	targets := map[string]string{}
	for _, ep := range eps {
		targets[ep.DNSName] = ep.Targets[0]
	}
	if targets["bare.woven"] != t1+".cfargotunnel.com" {
		t.Errorf("bare.woven target = %q, want %s tunnel target", targets["bare.woven"], t1)
	}
	if targets["svc.apps.woven"] != t2+".cfargotunnel.com" {
		t.Errorf("svc.apps.woven target = %q, want %s tunnel target", targets["svc.apps.woven"], t2)
	}
}

func TestNew_RequiresTunnel(t *testing.T) {
	if _, err := New(Config{Client: &fakeAPI{}}); err == nil {
		t.Fatal("expected error when neither TunnelID nor TunnelMap is set")
	}
}

func names(eps []*endpoint.Endpoint) []string {
	out := make([]string, 0, len(eps))
	for _, e := range eps {
		out = append(out, e.DNSName)
	}
	return out
}
