// Package metrics defines the Prometheus collectors for the Cloudflare Zero Trust
// webhook provider. Collectors are created against a caller-supplied registry (rather
// than the global default) so tests can use a fresh registry and the process can expose
// exactly this provider's series. Every method is nil-safe: a nil *Metrics is a no-op,
// which lets the provider run without metrics wired in (e.g. in unit tests).
package metrics

import "github.com/prometheus/client_golang/prometheus"

const (
	namespace = "cfzt"
	subsystem = "provider"
)

// API operation label values for the api_requests_total counter.
const (
	OpList   = "list"
	OpCreate = "create"
	OpDelete = "delete"
)

// Metrics holds the provider's Prometheus collectors.
type Metrics struct {
	apiRequests    *prometheus.CounterVec
	routesCreated  prometheus.Counter
	routesDeleted  prometheus.Counter
	applyDuration  prometheus.Histogram
	recordsManaged prometheus.Gauge
}

// New builds the collectors (unregistered). Call MustRegister to attach them to a registry.
func New() *Metrics {
	return &Metrics{
		apiRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Subsystem: subsystem, Name: "api_requests_total",
			Help: "Cloudflare Zero Trust hostname-route API requests, by operation and result.",
		}, []string{"operation", "result"}),
		routesCreated: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace, Subsystem: subsystem, Name: "routes_created_total",
			Help: "Hostname routes created by this provider.",
		}),
		routesDeleted: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace, Subsystem: subsystem, Name: "routes_deleted_total",
			Help: "Hostname routes deleted by this provider.",
		}),
		applyDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace, Subsystem: subsystem, Name: "apply_duration_seconds",
			Help:    "Duration of ApplyChanges reconciliations, in seconds.",
			Buckets: prometheus.DefBuckets,
		}),
		recordsManaged: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: subsystem, Name: "records_managed",
			Help: "Managed hostname routes observed on the most recent Records() call.",
		}),
	}
}

// MustRegister attaches all collectors to reg, panicking on duplicate registration.
func (m *Metrics) MustRegister(reg prometheus.Registerer) {
	reg.MustRegister(
		m.apiRequests,
		m.routesCreated,
		m.routesDeleted,
		m.applyDuration,
		m.recordsManaged,
	)
}

// APIRequest records one CF API call, labelling the result success/error from err.
func (m *Metrics) APIRequest(operation string, err error) {
	if m == nil {
		return
	}
	result := "success"
	if err != nil {
		result = "error"
	}
	m.apiRequests.WithLabelValues(operation, result).Inc()
}

// RouteCreated increments the created-routes counter.
func (m *Metrics) RouteCreated() {
	if m == nil {
		return
	}
	m.routesCreated.Inc()
}

// RouteDeleted increments the deleted-routes counter.
func (m *Metrics) RouteDeleted() {
	if m == nil {
		return
	}
	m.routesDeleted.Inc()
}

// ObserveApply records the duration of one ApplyChanges call, in seconds.
func (m *Metrics) ObserveApply(seconds float64) {
	if m == nil {
		return
	}
	m.applyDuration.Observe(seconds)
}

// SetRecordsManaged records the count of managed routes seen by the last Records() call.
func (m *Metrics) SetRecordsManaged(n int) {
	if m == nil {
		return
	}
	m.recordsManaged.Set(float64(n))
}
