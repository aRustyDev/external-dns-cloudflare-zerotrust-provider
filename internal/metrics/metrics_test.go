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
