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

package provider

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"

	"github.com/arustydev/external-dns-cloudflare-zerotrust-provider/internal/cloudflare"
	"github.com/arustydev/external-dns-cloudflare-zerotrust-provider/internal/metrics"
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
	patched        []string // route ids patched, in order
	patchComments  []string
	patchErr       error
	createErr      error
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
	if f.createErr != nil {
		return nil, f.createErr
	}
	f.nextID++
	r := cloudflare.HostnameRoute{ID: "id-" + hostname, Hostname: hostname, TunnelID: tunnelID, Comment: comment}
	f.routes = append(f.routes, r)
	f.created = append(f.created, hostname)
	f.createdTunnels = append(f.createdTunnels, tunnelID)
	return &r, nil
}

// PatchHostnameRouteComment mirrors the live API: it rewrites the comment IN PLACE, keeping the
// route id, hostname and tunnel binding — the property that makes adoption zero-downtime.
func (f *fakeAPI) PatchHostnameRouteComment(_ context.Context, id, comment string) (*cloudflare.HostnameRoute, error) {
	if f.patchErr != nil {
		return nil, f.patchErr
	}
	f.patched = append(f.patched, id)
	f.patchComments = append(f.patchComments, comment)
	for i := range f.routes {
		if f.routes[i].ID == id {
			f.routes[i].Comment = comment
			r := f.routes[i]
			return &r, nil
		}
	}
	return nil, fmt.Errorf("no such route %q", id)
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
		{ID: "1", Hostname: "foo.private", TunnelID: testTunnel},
		{ID: "2", Hostname: "bar.example.com", TunnelID: testTunnel}, // out of domain filter
	}}
	p := newTestProvider(t, api, "private")

	eps, err := p.Records(context.Background())
	if err != nil {
		t.Fatalf("Records: %v", err)
	}
	if len(eps) != 1 {
		t.Fatalf("want 1 endpoint, got %d", len(eps))
	}
	if eps[0].DNSName != "foo.private" || eps[0].RecordType != endpoint.RecordTypeCNAME {
		t.Fatalf("unexpected endpoint: %+v", eps[0])
	}
	if got := eps[0].Targets[0]; got != testTunnel+".cfargotunnel.com" {
		t.Fatalf("target = %q, want tunnel target", got)
	}
}

func TestAdjustEndpoints_Canonicalizes(t *testing.T) {
	p := newTestProvider(t, &fakeAPI{}, "private")
	in := []*endpoint.Endpoint{
		endpoint.NewEndpoint("foo.private", endpoint.RecordTypeA, "10.0.0.5"), // wrong type+target
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

// The service source records which Service asked for a hostname in the "resource" label. That is
// the only channel carrying it to ApplyChanges, and answering the name in-cluster needs it (a
// CoreDNS rewrite is name->name, not name->IP), so canonicalization must not drop it.
func TestAdjustEndpoints_PreservesResourceLabel(t *testing.T) {
	p := newTestProvider(t, &fakeAPI{}, "private")
	in := endpoint.NewEndpoint("foo.private", endpoint.RecordTypeA, "10.0.0.5")
	in.Labels[endpoint.ResourceLabelKey] = "service/apps/foo-svc"

	out, err := p.AdjustEndpoints([]*endpoint.Endpoint{in})
	if err != nil {
		t.Fatalf("AdjustEndpoints: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("want 1 endpoint, got %d", len(out))
	}
	if got := out[0].Labels[endpoint.ResourceLabelKey]; got != "service/apps/foo-svc" {
		t.Errorf("resource label = %q, want it carried through canonicalization", got)
	}
	// Canonicalization itself must still happen.
	if out[0].RecordType != endpoint.RecordTypeCNAME {
		t.Errorf("record type = %q, want CNAME", out[0].RecordType)
	}
	// The input must not be mutated — the plan still holds a reference to it.
	if in.RecordType != endpoint.RecordTypeA {
		t.Errorf("input endpoint was mutated: %+v", in)
	}
}

func TestApplyChanges_CreateAndDelete(t *testing.T) {
	api := &fakeAPI{routes: []cloudflare.HostnameRoute{
		{ID: "id-old.private", Hostname: "old.private", TunnelID: testTunnel},
	}}
	p := newTestProvider(t, api, "private")

	target := p.resolver.target(testTunnel)
	changes := &plan.Changes{
		Create: []*endpoint.Endpoint{endpoint.NewEndpoint("new.private", endpoint.RecordTypeCNAME, target)},
		Delete: []*endpoint.Endpoint{endpoint.NewEndpoint("old.private", endpoint.RecordTypeCNAME, target)},
	}
	if err := p.ApplyChanges(context.Background(), changes); err != nil {
		t.Fatalf("ApplyChanges: %v", err)
	}
	if len(api.created) != 1 || api.created[0] != "new.private" {
		t.Fatalf("created = %v, want [new.private]", api.created)
	}
	if len(api.deleted) != 1 || api.deleted[0] != "id-old.private" {
		t.Fatalf("deleted = %v, want [id-old.private]", api.deleted)
	}
}

func TestApplyChanges_NilIsNoop(t *testing.T) {
	api := &fakeAPI{}
	p := newTestProvider(t, api, "private")
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
		{ID: "1", Hostname: "mine.private", TunnelID: testTunnel, Comment: "managed-by=external-dns/test"},
		{ID: "2", Hostname: "theirs.private", TunnelID: testTunnel, Comment: "managed-by=external-dns/other"},
		{ID: "3", Hostname: "manual.private", TunnelID: testTunnel, Comment: "hand-created"},
	}}

	// Strict: only our own route surfaces.
	strict := strictProvider(t, api, "test", "private")
	eps, err := strict.Records(context.Background())
	if err != nil {
		t.Fatalf("Records: %v", err)
	}
	if len(eps) != 1 || eps[0].DNSName != "mine.private" {
		t.Fatalf("strict Records = %v, want [mine.private]", names(eps))
	}

	// Non-strict: all domain-matching routes surface, regardless of owner.
	loose := newTestProvider(t, api, "private")
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
		{ID: "id-mine.private", Hostname: "mine.private", TunnelID: testTunnel, Comment: "managed-by=external-dns/test"},
		{ID: "id-manual.private", Hostname: "manual.private", TunnelID: testTunnel, Comment: "hand-created"},
	}}
	p := strictProvider(t, api, "test", "private")

	// Ask to delete both; only the owned one may actually be deleted.
	changes := &plan.Changes{Delete: []*endpoint.Endpoint{
		endpoint.NewEndpoint("mine.private", endpoint.RecordTypeCNAME, p.resolver.target(testTunnel)),
		endpoint.NewEndpoint("manual.private", endpoint.RecordTypeCNAME, p.resolver.target(testTunnel)),
	}}
	if err := p.ApplyChanges(context.Background(), changes); err != nil {
		t.Fatalf("ApplyChanges: %v", err)
	}
	if len(api.deleted) != 1 || api.deleted[0] != "id-mine.private" {
		t.Fatalf("deleted = %v, want only [id-mine.private] (never the hand-created route)", api.deleted)
	}
}

func TestMultiTunnel_CreateRoutesToMostSpecificTunnel(t *testing.T) {
	const t1, t2 = "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"
	api := &fakeAPI{}
	p, err := New(Config{
		Client:       api,
		TunnelMap:    map[string]string{"private": t1, "apps.private": t2},
		OwnerID:      "test",
		DomainFilter: []string{"private"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	changes := &plan.Changes{Create: []*endpoint.Endpoint{
		endpoint.NewEndpoint("svc.apps.private", endpoint.RecordTypeCNAME, ""), // -> apps.private tunnel (t2)
		endpoint.NewEndpoint("bare.private", endpoint.RecordTypeCNAME, ""),     // -> private tunnel (t1)
	}}
	if err := p.ApplyChanges(context.Background(), changes); err != nil {
		t.Fatalf("ApplyChanges: %v", err)
	}

	got := map[string]string{}
	for i, h := range api.created {
		got[h] = api.createdTunnels[i]
	}
	if got["svc.apps.private"] != t2 {
		t.Errorf("svc.apps.private bound to %q, want most-specific tunnel %q", got["svc.apps.private"], t2)
	}
	if got["bare.private"] != t1 {
		t.Errorf("bare.private bound to %q, want %q", got["bare.private"], t1)
	}
}

func TestMultiTunnel_RecordsUsesPerTunnelTarget(t *testing.T) {
	const t1, t2 = "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"
	api := &fakeAPI{routes: []cloudflare.HostnameRoute{
		{ID: "1", Hostname: "bare.private", TunnelID: t1},
		{ID: "2", Hostname: "svc.apps.private", TunnelID: t2},
	}}
	p, err := New(Config{
		Client:       api,
		TunnelMap:    map[string]string{"private": t1, "apps.private": t2},
		DomainFilter: []string{"private"},
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
	if targets["bare.private"] != t1+".cfargotunnel.com" {
		t.Errorf("bare.private target = %q, want %s tunnel target", targets["bare.private"], t1)
	}
	if targets["svc.apps.private"] != t2+".cfargotunnel.com" {
		t.Errorf("svc.apps.private target = %q, want %s tunnel target", targets["svc.apps.private"], t2)
	}
}

func TestNew_RequiresTunnel(t *testing.T) {
	if _, err := New(Config{Client: &fakeAPI{}}); err == nil {
		t.Fatal("expected error when neither TunnelID nor TunnelMap is set")
	}
}

// --- dry run (infra-415m.12) ---------------------------------------------------------------
//
// ExternalDNS's own --dry-run never reaches a webhook provider, so DRY_RUN here is the only
// thing standing between a reconcile and a live Cloudflare account. These tests assert on the
// EXPORTED metric series, because that is what an operator alerts on.

// dryRunHarness builds a provider wired to a fresh registry and a capturing logger.
func dryRunHarness(t *testing.T, api routeAPI, dryRun bool) (*Provider, *prometheus.Registry, *bytes.Buffer) {
	t.Helper()
	reg := prometheus.NewRegistry()
	m := metrics.New()
	m.MustRegister(reg)
	var logs bytes.Buffer
	p, err := New(Config{
		Client:          api,
		TunnelID:        testTunnel,
		OwnerID:         "test",
		OwnershipStrict: true,
		DryRun:          dryRun,
		DomainFilter:    []string{"private"},
		Metrics:         m,
		Logger:          slog.New(slog.NewTextHandler(&logs, nil)),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p, reg, &logs
}

// metricValue reads one sample from a gathered registry by family name and exact label set.
// The metrics package keeps its collectors unexported, so we go through the registry rather
// than testutil.ToFloat64. A series that was never touched reports 0.
func metricValue(t *testing.T, reg *prometheus.Registry, name string, labels map[string]string) float64 {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range families {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			got := map[string]string{}
			for _, lp := range m.GetLabel() {
				got[lp.GetName()] = lp.GetValue()
			}
			if len(got) != len(labels) {
				continue
			}
			match := true
			for k, v := range labels {
				if got[k] != v {
					match = false
					break
				}
			}
			if !match {
				continue
			}
			switch {
			case m.Counter != nil:
				return m.Counter.GetValue()
			case m.Gauge != nil:
				return m.Gauge.GetValue()
			}
		}
	}
	return 0
}

// dryRunAPI holds one pre-existing route owned by us, so the delete path has something to find.
func dryRunAPI() *fakeAPI {
	return &fakeAPI{routes: []cloudflare.HostnameRoute{
		{ID: "id-old.private", Hostname: "old.private", TunnelID: testTunnel, Comment: "managed-by=external-dns/test"},
	}}
}

// dryRunPlan would create one route and delete the pre-existing one.
func dryRunPlan(p *Provider) *plan.Changes {
	target := p.resolver.target(testTunnel)
	return &plan.Changes{
		Create: []*endpoint.Endpoint{endpoint.NewEndpoint("new.private", endpoint.RecordTypeCNAME, target)},
		Delete: []*endpoint.Endpoint{endpoint.NewEndpoint("old.private", endpoint.RecordTypeCNAME, target)},
	}
}

func TestApplyChanges_DryRunMakesZeroMutatingCalls(t *testing.T) {
	api := dryRunAPI()
	p, reg, logs := dryRunHarness(t, api, true)
	changes := dryRunPlan(p)

	if err := p.ApplyChanges(context.Background(), changes); err != nil {
		t.Fatalf("ApplyChanges: %v", err)
	}

	// The whole point: nothing mutated.
	if len(api.created) != 0 || len(api.deleted) != 0 {
		t.Fatalf("dry run mutated Cloudflare: created=%v deleted=%v", api.created, api.deleted)
	}
	for _, op := range []string{metrics.OpCreate, metrics.OpDelete} {
		for _, result := range []string{"success", "error"} {
			labels := map[string]string{"operation": op, "result": result}
			if got := metricValue(t, reg, "cfzt_provider_api_requests_total", labels); got != 0 {
				t.Errorf("api_requests_total{%s,%s} = %v, want 0 in dry run", op, result, got)
			}
		}
	}
	if got := metricValue(t, reg, "cfzt_provider_routes_created_total", nil); got != 0 {
		t.Errorf("routes_created_total = %v, want 0", got)
	}
	if got := metricValue(t, reg, "cfzt_provider_routes_deleted_total", nil); got != 0 {
		t.Errorf("routes_deleted_total = %v, want 0", got)
	}

	// Read-only listing MUST still happen, otherwise the logged plan would be guesswork rather
	// than a diff against live state.
	listLabels := map[string]string{"operation": metrics.OpList, "result": "success"}
	if got := metricValue(t, reg, "cfzt_provider_api_requests_total", listLabels); got != 1 {
		t.Errorf("api_requests_total{list,success} = %v, want 1 (dry run still reads live state)", got)
	}

	// Observability: the gauge says "inert", the counters say "actively declining work".
	if got := metricValue(t, reg, "cfzt_provider_dry_run", nil); got != 1 {
		t.Errorf("dry_run gauge = %v, want 1", got)
	}
	if got := metricValue(t, reg, "cfzt_provider_dry_run_skipped_total", map[string]string{"operation": metrics.OpCreate}); got != 1 {
		t.Errorf("dry_run_skipped_total{create} = %v, want 1", got)
	}
	if got := metricValue(t, reg, "cfzt_provider_dry_run_skipped_total", map[string]string{"operation": metrics.OpDelete}); got != 1 {
		t.Errorf("dry_run_skipped_total{delete} = %v, want 1", got)
	}

	// And the intended changes are actually reported, including the route id we would delete.
	out := logs.String()
	for _, want := range []string{"would CREATE", "new.private", "would DELETE", "old.private", "id-old.private"} {
		if !strings.Contains(out, want) {
			t.Errorf("dry-run log missing %q; got:\n%s", want, out)
		}
	}
}

func TestApplyChanges_DryRunOffStillMutates(t *testing.T) {
	api := dryRunAPI()
	p, reg, _ := dryRunHarness(t, api, false)
	changes := dryRunPlan(p)

	if err := p.ApplyChanges(context.Background(), changes); err != nil {
		t.Fatalf("ApplyChanges: %v", err)
	}
	if len(api.created) != 1 || api.created[0] != "new.private" {
		t.Errorf("created = %v, want [new.private] when DryRun is off", api.created)
	}
	if len(api.deleted) != 1 || api.deleted[0] != "id-old.private" {
		t.Errorf("deleted = %v, want [id-old.private] when DryRun is off", api.deleted)
	}
	if got := metricValue(t, reg, "cfzt_provider_dry_run", nil); got != 0 {
		t.Errorf("dry_run gauge = %v, want 0", got)
	}
	if got := metricValue(t, reg, "cfzt_provider_dry_run_skipped_total", map[string]string{"operation": metrics.OpCreate}); got != 0 {
		t.Errorf("dry_run_skipped_total{create} = %v, want 0", got)
	}
}

// Dry run is a validation pass, not a bypass: a hostname with no configured tunnel must still
// fail loudly rather than be silently reported as fine.
func TestApplyChanges_DryRunStillValidatesTunnelSelection(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := metrics.New()
	m.MustRegister(reg)
	p, err := New(Config{
		Client:       &fakeAPI{},
		TunnelMap:    map[string]string{"apps.private": testTunnel},
		OwnerID:      "test",
		DryRun:       true,
		DomainFilter: []string{"private"},
		Metrics:      m,
		Logger:       slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	changes := &plan.Changes{Create: []*endpoint.Endpoint{
		endpoint.NewEndpoint("orphan.private", endpoint.RecordTypeCNAME, ""), // matches no mapped domain
	}}
	if err := p.ApplyChanges(context.Background(), changes); err == nil {
		t.Fatal("dry run should still reject a hostname with no configured tunnel")
	}
}

// --- route adoption (infra-415m.8) ---------------------------------------------------------
//
// Cloudflare REJECTS a duplicate hostname route (409 / error 1108, live-verified), so a create
// for an already-routed hostname cannot succeed. Adoption claims the existing route by comment
// PATCH instead, keeping the route id and tunnel binding so DNS never stops resolving.

// adoptHarness builds an adoption-enabled provider over api, plus its registry and log buffer.
func adoptHarness(t *testing.T, api routeAPI, adopt bool) (*Provider, *prometheus.Registry, *bytes.Buffer) {
	t.Helper()
	reg := prometheus.NewRegistry()
	m := metrics.New()
	m.MustRegister(reg)
	var logs bytes.Buffer
	p, err := New(Config{
		Client:          api,
		TunnelID:        testTunnel,
		OwnerID:         "test",
		OwnershipStrict: true,
		AdoptUntagged:   adopt,
		DomainFilter:    []string{"private"},
		Metrics:         m,
		Logger:          slog.New(slog.NewTextHandler(&logs, nil)),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p, reg, &logs
}

func createPlan(p *Provider, host string) *plan.Changes {
	return &plan.Changes{Create: []*endpoint.Endpoint{
		endpoint.NewEndpoint(host, endpoint.RecordTypeCNAME, p.resolver.target(testTunnel)),
	}}
}

// The headline property: adoption is an in-place comment rewrite, NOT a delete/recreate.
func TestAdopt_ClaimsUntaggedRouteInPlace(t *testing.T) {
	api := &fakeAPI{routes: []cloudflare.HostnameRoute{
		{ID: "tf-route-id", Hostname: "legacy.private", TunnelID: testTunnel, Comment: "managed by opentofu"},
	}}
	p, reg, logs := adoptHarness(t, api, true)

	if err := p.ApplyChanges(context.Background(), createPlan(p, "legacy.private")); err != nil {
		t.Fatalf("ApplyChanges: %v", err)
	}

	if len(api.patched) != 1 || api.patched[0] != "tf-route-id" {
		t.Fatalf("patched = %v, want [tf-route-id]", api.patched)
	}
	if got := api.patchComments[0]; got != "managed-by=external-dns/test" {
		t.Errorf("new comment = %q, want this owner's tag", got)
	}
	// No delete, no create — that is what "zero DNS interruption" means here.
	if len(api.created) != 0 || len(api.deleted) != 0 {
		t.Errorf("adoption must not create or delete: created=%v deleted=%v", api.created, api.deleted)
	}
	// The route id is unchanged, so the hostname->tunnel binding never lapsed.
	if api.routes[0].ID != "tf-route-id" || api.routes[0].TunnelID != testTunnel {
		t.Errorf("route identity changed: %+v", api.routes[0])
	}
	if got := metricValue(t, reg, "cfzt_provider_routes_adopted_total", nil); got != 1 {
		t.Errorf("routes_adopted_total = %v, want 1", got)
	}
	if got := metricValue(t, reg, "cfzt_provider_routes_created_total", nil); got != 0 {
		t.Errorf("routes_created_total = %v, want 0 (adoption is not a create)", got)
	}
	if got := metricValue(t, reg, "cfzt_provider_api_requests_total", map[string]string{"operation": "patch", "result": "success"}); got != 1 {
		t.Errorf("api_requests_total{patch,success} = %v, want 1", got)
	}
	// The overwritten comment is the only record of the previous claim, so it must be logged.
	if out := logs.String(); !strings.Contains(out, "managed by opentofu") {
		t.Errorf("adoption log must record the old comment; got:\n%s", out)
	}
}

func TestAdopt_DisabledByDefaultStillCreates(t *testing.T) {
	api := &fakeAPI{}
	p, _, _ := adoptHarness(t, api, false)

	if err := p.ApplyChanges(context.Background(), createPlan(p, "fresh.private")); err != nil {
		t.Fatalf("ApplyChanges: %v", err)
	}
	if len(api.patched) != 0 {
		t.Errorf("nothing should be patched when adoption is off: %v", api.patched)
	}
	if len(api.created) != 1 {
		t.Errorf("created = %v, want the normal create path", api.created)
	}
}

// With adoption OFF, an existing route is not even looked at — the create runs and Cloudflare
// 409s. Assert the error carries the actionable hint rather than the raw vendor message.
func TestAdopt_OffSurfacesAlreadyRoutedHint(t *testing.T) {
	api := &fakeAPI{createErr: &cloudflare.APIError{
		Method: "POST", StatusCode: 409,
		Codes:   []int{cloudflare.ErrCodeHostnameAlreadyRouted},
		Message: "[1108] Hostname Route already routed to another tunnel",
	}}
	p, _, _ := adoptHarness(t, api, false)

	err := p.ApplyChanges(context.Background(), createPlan(p, "legacy.private"))
	if err == nil {
		t.Fatal("want an error when Cloudflare rejects the duplicate")
	}
	if !strings.Contains(err.Error(), "ADOPT_UNTAGGED=true") {
		t.Errorf("error should point at the fix; got: %v", err)
	}
	var apiErr *cloudflare.APIError
	if !errors.As(err, &apiErr) {
		t.Errorf("error should still wrap the APIError for code inspection; got %T", err)
	}
}

func TestAdopt_RefusesRouteOnDifferentTunnel(t *testing.T) {
	const otherTunnel = "99999999-9999-9999-9999-999999999999"
	api := &fakeAPI{routes: []cloudflare.HostnameRoute{
		{ID: "elsewhere", Hostname: "legacy.private", TunnelID: otherTunnel, Comment: "untagged"},
	}}
	p, _, _ := adoptHarness(t, api, true)

	// The guard is exercised directly rather than through ApplyChanges: in single-tunnel mode a
	// route on another tunnel is never listed, so it cannot reach adopt(). The reachable path is
	// multi-tunnel mode, where several tunnels are listed and a hostname can resolve to one
	// tunnel while its existing route sits on another. That is the collision this refuses.
	err := p.adopt(context.Background(), api.routes[0], testTunnel)
	if err == nil {
		t.Fatal("want refusal: the route is bound to a different tunnel")
	}
	if !strings.Contains(err.Error(), otherTunnel) {
		t.Errorf("error should name the conflicting tunnel; got: %v", err)
	}
	if len(api.patched) != 0 {
		t.Errorf("must not patch a route on another tunnel: %v", api.patched)
	}
}

func TestAdopt_RefusesRouteOwnedByAnotherExternalDNS(t *testing.T) {
	api := &fakeAPI{routes: []cloudflare.HostnameRoute{
		{ID: "theirs", Hostname: "legacy.private", TunnelID: testTunnel, Comment: "managed-by=external-dns/other-cluster"},
	}}
	p, _, _ := adoptHarness(t, api, true)

	err := p.ApplyChanges(context.Background(), createPlan(p, "legacy.private"))
	if err == nil {
		t.Fatal("want refusal: the route belongs to a different external-dns owner")
	}
	if !strings.Contains(err.Error(), "other-cluster") {
		t.Errorf("error should name the owner; got: %v", err)
	}
	if len(api.patched) != 0 {
		t.Errorf("must not steal another owner's route: %v", api.patched)
	}
}

// A route already carrying OUR tag needs no PATCH — adoption must be idempotent, not a
// write-amplifier that re-stamps the same comment on every reconcile.
func TestAdopt_AlreadyOursIsANoop(t *testing.T) {
	api := &fakeAPI{routes: []cloudflare.HostnameRoute{
		{ID: "mine", Hostname: "legacy.private", TunnelID: testTunnel, Comment: "managed-by=external-dns/test"},
	}}
	p, reg, _ := adoptHarness(t, api, true)

	if err := p.ApplyChanges(context.Background(), createPlan(p, "legacy.private")); err != nil {
		t.Fatalf("ApplyChanges: %v", err)
	}
	if len(api.patched) != 0 || len(api.created) != 0 {
		t.Errorf("already-owned route needs no write: patched=%v created=%v", api.patched, api.created)
	}
	if got := metricValue(t, reg, "cfzt_provider_routes_adopted_total", nil); got != 0 {
		t.Errorf("routes_adopted_total = %v, want 0 (nothing was newly claimed)", got)
	}
}

// Adoption is a mutation, so DRY_RUN must suppress the PATCH too — otherwise the dry-run guard
// would have a hole exactly where the migration does its riskiest work.
func TestAdopt_DryRunSuppressesThePatch(t *testing.T) {
	api := &fakeAPI{routes: []cloudflare.HostnameRoute{
		{ID: "tf-route-id", Hostname: "legacy.private", TunnelID: testTunnel, Comment: "managed by opentofu"},
	}}
	reg := prometheus.NewRegistry()
	m := metrics.New()
	m.MustRegister(reg)
	var logs bytes.Buffer
	p, err := New(Config{
		Client: api, TunnelID: testTunnel, OwnerID: "test", OwnershipStrict: true,
		AdoptUntagged: true, DryRun: true, DomainFilter: []string{"private"},
		Metrics: m, Logger: slog.New(slog.NewTextHandler(&logs, nil)),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := p.ApplyChanges(context.Background(), createPlan(p, "legacy.private")); err != nil {
		t.Fatalf("ApplyChanges: %v", err)
	}
	if len(api.patched) != 0 {
		t.Fatalf("dry run must not PATCH: %v", api.patched)
	}
	if api.routes[0].Comment != "managed by opentofu" {
		t.Errorf("dry run mutated the comment: %q", api.routes[0].Comment)
	}
	if got := metricValue(t, reg, "cfzt_provider_dry_run_skipped_total", map[string]string{"operation": "patch"}); got != 1 {
		t.Errorf("dry_run_skipped_total{patch} = %v, want 1", got)
	}
	if got := metricValue(t, reg, "cfzt_provider_routes_adopted_total", nil); got != 0 {
		t.Errorf("routes_adopted_total = %v, want 0 in dry run", got)
	}
	if out := logs.String(); !strings.Contains(out, "would ADOPT") {
		t.Errorf("dry run should report the intended adoption; got:\n%s", out)
	}
}

// --- CoreDNS leg / leg 2 (infra-415m.10) ----------------------------------------------------

// fakeFragment records calls and can fail on demand. It also stamps an ordering marker so tests
// can prove the fragment write happens BEFORE any Cloudflare mutation.
type fakeFragment struct {
	applies  []fragmentCall
	err      error
	order    *[]string
	rewrites map[string]string
}

type fragmentCall struct {
	add    map[string]string
	remove []string
}

func (f *fakeFragment) Key() string { return "zz-external-dns.override" }

func (f *fakeFragment) ServiceTarget(resource string) (string, error) {
	kind, rest, ok := strings.Cut(resource, "/")
	if !ok || kind != "service" {
		return "", fmt.Errorf("unsupported resource %q", resource)
	}
	ns, name, ok := strings.Cut(rest, "/")
	if !ok || ns == "" || name == "" {
		return "", fmt.Errorf("malformed resource %q", resource)
	}
	return name + "." + ns + ".svc.cluster.local", nil
}

func (f *fakeFragment) Apply(_ context.Context, add map[string]string, remove []string) (map[string]string, error) {
	if f.order != nil {
		*f.order = append(*f.order, "fragment")
	}
	if f.err != nil {
		return nil, f.err
	}
	f.applies = append(f.applies, fragmentCall{add: add, remove: remove})
	if f.rewrites == nil {
		f.rewrites = map[string]string{}
	}
	for _, h := range remove {
		delete(f.rewrites, h)
	}
	for h, t := range add {
		f.rewrites[h] = t
	}
	return f.rewrites, nil
}

// orderingAPI wraps fakeAPI to record when Cloudflare mutations happen relative to the fragment.
type orderingAPI struct {
	*fakeAPI
	order *[]string
}

func (o *orderingAPI) CreateHostnameRoute(ctx context.Context, hostname, tunnelID, comment string) (*cloudflare.HostnameRoute, error) {
	*o.order = append(*o.order, "cf-create")
	return o.fakeAPI.CreateHostnameRoute(ctx, hostname, tunnelID, comment)
}

func (o *orderingAPI) DeleteHostnameRoute(ctx context.Context, id string) error {
	*o.order = append(*o.order, "cf-delete")
	return o.fakeAPI.DeleteHostnameRoute(ctx, id)
}

func corednsHarness(t *testing.T, api routeAPI, frag FragmentWriter, dryRun bool) (*Provider, *prometheus.Registry, *bytes.Buffer) {
	t.Helper()
	reg := prometheus.NewRegistry()
	m := metrics.New()
	m.MustRegister(reg)
	var logs bytes.Buffer
	p, err := New(Config{
		Client: api, TunnelID: testTunnel, OwnerID: "test", OwnershipStrict: true,
		CoreDNS: frag, DryRun: dryRun, DomainFilter: []string{"woven"},
		Metrics: m, Logger: slog.New(slog.NewTextHandler(&logs, nil)),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p, reg, &logs
}

func svcEndpoint(host, resource string) *endpoint.Endpoint {
	ep := endpoint.NewEndpoint(host, endpoint.RecordTypeCNAME, "")
	if resource != "" {
		ep.Labels[endpoint.ResourceLabelKey] = resource
	}
	return ep
}

func TestCoreDNS_WritesBothLegsFromOneAnnotation(t *testing.T) {
	api := &fakeAPI{}
	frag := &fakeFragment{}
	p, reg, _ := corednsHarness(t, api, frag, false)

	changes := &plan.Changes{Create: []*endpoint.Endpoint{
		svcEndpoint("foo.edns.woven", "service/apps/foo"),
	}}
	if err := p.ApplyChanges(context.Background(), changes); err != nil {
		t.Fatalf("ApplyChanges: %v", err)
	}

	// Leg 1.
	if len(api.created) != 1 || api.created[0] != "foo.edns.woven" {
		t.Errorf("cloudflare route not created: %v", api.created)
	}
	// Leg 2.
	if len(frag.applies) != 1 {
		t.Fatalf("want 1 fragment write, got %d", len(frag.applies))
	}
	if got := frag.applies[0].add["foo.edns.woven"]; got != "foo.apps.svc.cluster.local" {
		t.Errorf("rewrite target = %q, want the Service's cluster-local name", got)
	}
	if got := metricValue(t, reg, "cfzt_provider_coredns_rewrites", nil); got != 1 {
		t.Errorf("coredns_rewrites = %v, want 1", got)
	}
	if got := metricValue(t, reg, "cfzt_provider_coredns_writes_total", map[string]string{"result": "success"}); got != 1 {
		t.Errorf("coredns_writes_total{success} = %v, want 1", got)
	}
}

// THE convergence property: the fragment must be written BEFORE Cloudflare. ExternalDNS plans from
// Records(), which reads Cloudflare, so if Cloudflare went first a failed fragment write would
// leave the plan with nothing to retry and the hostname permanently half-configured.
func TestCoreDNS_FragmentIsWrittenBeforeCloudflare(t *testing.T) {
	var order []string
	base := &fakeAPI{routes: []cloudflare.HostnameRoute{
		{ID: "id-old.edns.woven", Hostname: "old.edns.woven", TunnelID: testTunnel, Comment: "managed-by=external-dns/test"},
	}}
	api := &orderingAPI{fakeAPI: base, order: &order}
	frag := &fakeFragment{order: &order}
	p, _, _ := corednsHarness(t, api, frag, false)

	changes := &plan.Changes{
		Create: []*endpoint.Endpoint{svcEndpoint("new.edns.woven", "service/apps/new")},
		Delete: []*endpoint.Endpoint{svcEndpoint("old.edns.woven", "service/apps/old")},
	}
	if err := p.ApplyChanges(context.Background(), changes); err != nil {
		t.Fatalf("ApplyChanges: %v", err)
	}
	if len(order) == 0 || order[0] != "fragment" {
		t.Fatalf("fragment must be written first, got order %v", order)
	}
	for _, step := range order[1:] {
		if step == "fragment" {
			t.Errorf("fragment written more than once: %v (want ONE batched write)", order)
		}
	}
}

// A failed fragment write must abort before Cloudflare is touched, so the next reconcile still
// plans the same change.
func TestCoreDNS_WriteFailureLeavesCloudflareUntouched(t *testing.T) {
	api := &fakeAPI{}
	frag := &fakeFragment{err: errors.New("configmap conflict")}
	p, reg, _ := corednsHarness(t, api, frag, false)

	err := p.ApplyChanges(context.Background(), &plan.Changes{
		Create: []*endpoint.Endpoint{svcEndpoint("foo.edns.woven", "service/apps/foo")},
	})
	if err == nil {
		t.Fatal("want an error when the fragment write fails")
	}
	if len(api.created) != 0 {
		t.Errorf("cloudflare was mutated despite the fragment failing: %v", api.created)
	}
	if got := metricValue(t, reg, "cfzt_provider_coredns_writes_total", map[string]string{"result": "error"}); got != 1 {
		t.Errorf("coredns_writes_total{error} = %v, want 1", got)
	}
}

// Without the resource label the backing Service is unknown. Creating leg 1 anyway would yield a
// hostname that never resolves, so this must fail loudly instead.
func TestCoreDNS_MissingResourceLabelIsAnError(t *testing.T) {
	api := &fakeAPI{}
	frag := &fakeFragment{}
	p, _, _ := corednsHarness(t, api, frag, false)

	err := p.ApplyChanges(context.Background(), &plan.Changes{
		Create: []*endpoint.Endpoint{svcEndpoint("foo.edns.woven", "")},
	})
	if err == nil {
		t.Fatal("want an error when the endpoint carries no resource label")
	}
	if !strings.Contains(err.Error(), "resource") {
		t.Errorf("error should name the missing label; got: %v", err)
	}
	if len(api.created) != 0 || len(frag.applies) != 0 {
		t.Error("nothing should have been written")
	}
}

// A non-Service resource (e.g. an Ingress) cannot be mapped to one cluster-local name.
func TestCoreDNS_NonServiceResourceIsAnError(t *testing.T) {
	p, _, _ := corednsHarness(t, &fakeAPI{}, &fakeFragment{}, false)
	err := p.ApplyChanges(context.Background(), &plan.Changes{
		Create: []*endpoint.Endpoint{svcEndpoint("foo.edns.woven", "ingress/apps/foo")},
	})
	if err == nil {
		t.Fatal("want an error for a non-Service resource")
	}
}

func TestCoreDNS_DeleteRemovesTheRewrite(t *testing.T) {
	api := &fakeAPI{routes: []cloudflare.HostnameRoute{
		{ID: "id-gone.edns.woven", Hostname: "gone.edns.woven", TunnelID: testTunnel, Comment: "managed-by=external-dns/test"},
	}}
	frag := &fakeFragment{rewrites: map[string]string{"gone.edns.woven": "gone.apps.svc.cluster.local"}}
	p, _, _ := corednsHarness(t, api, frag, false)

	if err := p.ApplyChanges(context.Background(), &plan.Changes{
		Delete: []*endpoint.Endpoint{svcEndpoint("gone.edns.woven", "service/apps/gone")},
	}); err != nil {
		t.Fatalf("ApplyChanges: %v", err)
	}
	if len(frag.applies) != 1 || len(frag.applies[0].remove) != 1 ||
		frag.applies[0].remove[0] != "gone.edns.woven" {
		t.Fatalf("fragment removals = %+v", frag.applies)
	}
	if _, still := frag.rewrites["gone.edns.woven"]; still {
		t.Error("rewrite survived the delete")
	}
	if len(api.deleted) != 1 {
		t.Errorf("cloudflare route not deleted: %v", api.deleted)
	}
}

// DRY_RUN must gate the ConfigMap write too, or the guard has a hole in the leg that mutates the
// cluster rather than Cloudflare.
func TestCoreDNS_DryRunSuppressesTheWrite(t *testing.T) {
	api := &fakeAPI{}
	frag := &fakeFragment{}
	p, reg, logs := corednsHarness(t, api, frag, true)

	if err := p.ApplyChanges(context.Background(), &plan.Changes{
		Create: []*endpoint.Endpoint{svcEndpoint("foo.edns.woven", "service/apps/foo")},
	}); err != nil {
		t.Fatalf("ApplyChanges: %v", err)
	}
	if len(frag.applies) != 0 {
		t.Fatalf("dry run wrote the fragment: %+v", frag.applies)
	}
	if got := metricValue(t, reg, "cfzt_provider_dry_run_skipped_total", map[string]string{"operation": "fragment"}); got != 1 {
		t.Errorf("dry_run_skipped_total{fragment} = %v, want 1", got)
	}
	if out := logs.String(); !strings.Contains(out, "would UPDATE the CoreDNS fragment") {
		t.Errorf("dry run should report the intended fragment change; got:\n%s", out)
	}
}

// Leg 2 is opt-in: with no fragment writer the provider must behave exactly as before, and must
// NOT require the resource label.
func TestCoreDNS_DisabledByDefault(t *testing.T) {
	api := &fakeAPI{}
	p, _, _ := corednsHarness(t, api, nil, false)

	if err := p.ApplyChanges(context.Background(), &plan.Changes{
		Create: []*endpoint.Endpoint{svcEndpoint("foo.edns.woven", "")}, // no label at all
	}); err != nil {
		t.Fatalf("with no fragment writer this must succeed: %v", err)
	}
	if len(api.created) != 1 {
		t.Errorf("cloudflare route should still be created: %v", api.created)
	}
}

func names(eps []*endpoint.Endpoint) []string {
	out := make([]string, 0, len(eps))
	for _, e := range eps {
		out = append(out, e.DNSName)
	}
	return out
}
