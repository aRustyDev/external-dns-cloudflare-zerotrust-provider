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

package metrics

import (
	"errors"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestMetrics_RegisterAndCount(t *testing.T) {
	m := New()
	reg := prometheus.NewRegistry()
	m.MustRegister(reg) // must not panic on a fresh registry

	m.APIRequest(OpCreate, nil)
	m.APIRequest(OpCreate, errors.New("boom"))
	m.RouteCreated()
	m.RouteCreated()
	m.RouteDeleted()
	m.SetRecordsManaged(7)
	m.SetDryRun(true)
	m.DryRunSkipped(OpCreate)

	if got := testutil.ToFloat64(m.routesCreated); got != 2 {
		t.Errorf("routes_created_total = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.routesDeleted); got != 1 {
		t.Errorf("routes_deleted_total = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.recordsManaged); got != 7 {
		t.Errorf("records_managed = %v, want 7", got)
	}
	if got := testutil.ToFloat64(m.apiRequests.WithLabelValues(OpCreate, "success")); got != 1 {
		t.Errorf("api_requests_total{create,success} = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.apiRequests.WithLabelValues(OpCreate, "error")); got != 1 {
		t.Errorf("api_requests_total{create,error} = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.dryRun); got != 1 {
		t.Errorf("dry_run = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.dryRunSkipped.WithLabelValues(OpCreate)); got != 1 {
		t.Errorf("dry_run_skipped_total{create} = %v, want 1", got)
	}

	// The gauge must be able to go back down, otherwise it cannot clear an alert.
	m.SetDryRun(false)
	if got := testutil.ToFloat64(m.dryRun); got != 0 {
		t.Errorf("dry_run after SetDryRun(false) = %v, want 0", got)
	}
}

func TestMetrics_NilIsNoop(t *testing.T) {
	var m *Metrics // nil
	// None of these should panic.
	m.APIRequest(OpList, nil)
	m.RouteCreated()
	m.RouteDeleted()
	m.ObserveApply(0.5)
	m.SetRecordsManaged(3)
	m.SetDryRun(true)
	m.DryRunSkipped(OpCreate)
}

func TestMetrics_RoutesPendingWritesEveryReason(t *testing.T) {
	m := New()
	m.MustRegister(prometheus.NewRegistry())

	m.SetRoutesPending(map[string]int{PendingOther: 2, PendingSelf: 1})
	for reason, want := range map[string]float64{PendingSelf: 1, PendingOther: 2, PendingUntagged: 0, PendingUnknown: 0} {
		if got := testutil.ToFloat64(m.routesPending.WithLabelValues(reason)); got != want {
			t.Errorf("routes_pending{%s} = %v, want %v", reason, got, want)
		}
	}

	// A later call with no pending hosts must zero every reason, or an alert could never clear.
	m.SetRoutesPending(nil)
	for _, reason := range pendingReasons {
		if got := testutil.ToFloat64(m.routesPending.WithLabelValues(reason)); got != 0 {
			t.Errorf("routes_pending{%s} after clearing = %v, want 0", reason, got)
		}
	}
}

func TestMetrics_ListErrorCountsPerTunnel(t *testing.T) {
	m := New()
	m.MustRegister(prometheus.NewRegistry())

	m.ListError("tunnel-a")
	m.ListError("tunnel-a")
	m.ListError("account")
	if got := testutil.ToFloat64(m.listErrors.WithLabelValues("tunnel-a")); got != 2 {
		t.Errorf("list_errors_total{tunnel-a} = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.listErrors.WithLabelValues("account")); got != 1 {
		t.Errorf("list_errors_total{account} = %v, want 1", got)
	}
}

func TestMetrics_PendingAndListErrorNilIsNoop(t *testing.T) {
	var m *Metrics
	m.SetRoutesPending(map[string]int{PendingSelf: 1})
	m.ListError("tunnel-a")
}

func TestMetrics_RetargetByTunnelAndOrphanCollectors(t *testing.T) {
	m := New()
	m.MustRegister(prometheus.NewRegistry())

	m.RouteRetargeted()
	m.RouteRetargeted()
	if got := testutil.ToFloat64(m.routesRetarget); got != 2 {
		t.Errorf("routes_retargeted_total = %v, want 2", got)
	}

	// Zeros must be published: a draining tunnel at 0 is the signal it can be retired.
	m.SetRoutesByTunnel(map[string]int{"tunnel-a": 4, "tunnel-old": 0})
	if got := testutil.ToFloat64(m.routesByTunnel.WithLabelValues("tunnel-a")); got != 4 {
		t.Errorf("routes_by_tunnel{tunnel-a} = %v, want 4", got)
	}
	if got := testutil.CollectAndCount(m.routesByTunnel); got != 2 {
		t.Errorf("routes_by_tunnel has %d series, want 2 (the zero included)", got)
	}

	m.SetRoutesUndesired(3)
	m.SetRoutesOutOfFilter(2)
	if got := testutil.ToFloat64(m.routesUndesired); got != 3 {
		t.Errorf("routes_undesired = %v, want 3", got)
	}
	if got := testutil.ToFloat64(m.routesOutOfFilter); got != 2 {
		t.Errorf("routes_out_of_filter = %v, want 2", got)
	}
	// Gauges must be able to fall, or they could never clear an alert.
	m.SetRoutesUndesired(0)
	if got := testutil.ToFloat64(m.routesUndesired); got != 0 {
		t.Errorf("routes_undesired after clearing = %v, want 0", got)
	}

	m.CoreDNSPruned(2)
	m.CoreDNSPruned(1)
	if got := testutil.ToFloat64(m.corednsPruned); got != 3 {
		t.Errorf("coredns_pruned_total = %v, want 3", got)
	}
}

func TestMetrics_RetargetByTunnelAndOrphanNilIsNoop(t *testing.T) {
	var m *Metrics
	m.RouteRetargeted()
	m.SetRoutesByTunnel(map[string]int{"tunnel-a": 1})
	m.SetRoutesUndesired(1)
	m.SetRoutesOutOfFilter(1)
	m.CoreDNSPruned(1)
}
