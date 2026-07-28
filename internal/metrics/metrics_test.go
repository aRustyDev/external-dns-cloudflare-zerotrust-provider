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
}

func TestMetrics_NilIsNoop(t *testing.T) {
	var m *Metrics // nil
	// None of these should panic.
	m.APIRequest(OpList, nil)
	m.RouteCreated()
	m.RouteDeleted()
	m.ObserveApply(0.5)
	m.SetRecordsManaged(3)
}
