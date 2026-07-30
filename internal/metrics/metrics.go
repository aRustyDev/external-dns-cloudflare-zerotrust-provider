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
	OpPatch  = "patch"
)

// Metrics holds the provider's Prometheus collectors.
type Metrics struct {
	apiRequests    *prometheus.CounterVec
	routesCreated  prometheus.Counter
	routesDeleted  prometheus.Counter
	routesAdopted  prometheus.Counter
	applyDuration  prometheus.Histogram
	recordsManaged prometheus.Gauge
	dryRun         prometheus.Gauge
	dryRunSkipped  *prometheus.CounterVec
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
		routesAdopted: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace, Subsystem: subsystem, Name: "routes_adopted_total",
			Help: "Pre-existing hostname routes claimed in place by comment PATCH (no delete/recreate).",
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
		dryRun: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: subsystem, Name: "dry_run",
			Help: "1 when the provider suppresses all mutating Cloudflare calls (DRY_RUN), else 0.",
		}),
		dryRunSkipped: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Subsystem: subsystem, Name: "dry_run_skipped_total",
			Help: "Mutating Cloudflare calls suppressed by dry-run mode, by operation.",
		}, []string{"operation"}),
	}
}

// MustRegister attaches all collectors to reg, panicking on duplicate registration.
func (m *Metrics) MustRegister(reg prometheus.Registerer) {
	reg.MustRegister(
		m.apiRequests,
		m.routesCreated,
		m.routesDeleted,
		m.routesAdopted,
		m.applyDuration,
		m.recordsManaged,
		m.dryRun,
		m.dryRunSkipped,
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

// RouteAdopted increments the adopted-routes counter. Adoption rewrites an existing route's
// comment in place, so this is deliberately NOT counted as a create.
func (m *Metrics) RouteAdopted() {
	if m == nil {
		return
	}
	m.routesAdopted.Inc()
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

// SetDryRun publishes whether the provider is suppressing mutations. It is exported as a gauge
// so a long-running instance cannot be silently inert in the *other* direction: alert on
// cfzt_provider_dry_run == 1 to catch a deployment left in dry-run by accident.
func (m *Metrics) SetDryRun(on bool) {
	if m == nil {
		return
	}
	v := 0.0
	if on {
		v = 1
	}
	m.dryRun.Set(v)
}

// DryRunSkipped records one mutating call suppressed by dry-run mode. A rising value means the
// instance is actively being asked to change routes and declining — which is what makes the
// dry_run gauge actionable rather than merely informational.
func (m *Metrics) DryRunSkipped(operation string) {
	if m == nil {
		return
	}
	m.dryRunSkipped.WithLabelValues(operation).Inc()
}
