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

// Package coredns owns the in-cluster half of a private hostname: the CoreDNS answer that maps
// <host> to a Service's cluster-local name, so the tunnel connector can forward to its ClusterIP.
// The Cloudflare hostname route (the other half) is the internal/provider package's job; a name
// needs BOTH to resolve.
//
// # Why a ConfigMap fragment rather than etcd
//
// The target cluster's CoreDNS already imports every *.override file from a mounted ConfigMap and
// hot-reloads on change, and that ConfigMap is server-side-applied one key per owner. So it is
// already a dynamic backend: this package claims ONE key under its OWN field manager and never
// touches another owner's key or the base Corefile. No etcd, no CoreDNS reconfiguration, and none
// of the risk of re-rendering a shared single-owner Corefile.
//
// # Read-modify-write
//
// Server-side apply replaces a whole ConfigMap key, but the caller only ever learns about
// individual added/removed hosts. So Apply reads the key, parses the rewrites already in it,
// applies the delta, and writes the whole key back. The key IS the state — there is no second
// store to drift from it.
package coredns

import (
	"context"
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1apply "k8s.io/client-go/applyconfigurations/core/v1"
)

// DefaultKey is the ConfigMap data key this package owns. The zz- prefix keeps it last in the
// import glob's lexical order, matching the convention of the other per-owner fragments.
const DefaultKey = "zz-external-dns.override"

// DefaultFieldManager identifies our writes in the ConfigMap's managedFields. It must be unique
// to this writer: sharing a field manager with another owner is how keys get silently stolen.
const DefaultFieldManager = "external-dns"

// DefaultClusterDomain is the usual Kubernetes cluster domain.
const DefaultClusterDomain = "cluster.local"

// header is written at the top of the managed key so an operator reading the live ConfigMap knows
// not to hand-edit it.
const header = "# Managed by external-dns (cfzt webhook provider). Do not edit by hand."

// configMapAPI is the slice of the Kubernetes API this package needs. Narrow by design: a
// two-method interface is trivial to fake, where the generated ConfigMapInterface is not.
type configMapAPI interface {
	Get(ctx context.Context, name string, opts metav1.GetOptions) (*corev1.ConfigMap, error)
	Apply(ctx context.Context, cm *corev1apply.ConfigMapApplyConfiguration, opts metav1.ApplyOptions) (*corev1.ConfigMap, error)
}

// Fragment writes one key of a CoreDNS fragment ConfigMap.
type Fragment struct {
	api           configMapAPI
	name          string
	key           string
	fieldManager  string
	clusterDomain string
}

// Config configures a Fragment.
type Config struct {
	// API is a namespaced ConfigMap client, already scoped to the ConfigMap's namespace.
	API configMapAPI
	// Name is the ConfigMap name (e.g. "coredns-fragments").
	Name string
	// Key defaults to DefaultKey.
	Key string
	// FieldManager defaults to DefaultFieldManager.
	FieldManager string
	// ClusterDomain defaults to DefaultClusterDomain.
	ClusterDomain string
}

// New builds a Fragment.
func New(cfg Config) (*Fragment, error) {
	if cfg.API == nil {
		return nil, fmt.Errorf("a ConfigMap client is required")
	}
	if cfg.Name == "" {
		return nil, fmt.Errorf("a ConfigMap name is required")
	}
	f := &Fragment{
		api:           cfg.API,
		name:          cfg.Name,
		key:           cfg.Key,
		fieldManager:  cfg.FieldManager,
		clusterDomain: cfg.ClusterDomain,
	}
	if f.key == "" {
		f.key = DefaultKey
	}
	if f.fieldManager == "" {
		f.fieldManager = DefaultFieldManager
	}
	if f.clusterDomain == "" {
		f.clusterDomain = DefaultClusterDomain
	}
	return f, nil
}

// Key returns the ConfigMap data key this Fragment owns.
func (f *Fragment) Key() string { return f.key }

// ServiceTarget renders the cluster-local name a rewrite should point at. resource is the
// ExternalDNS resource label value, "service/<namespace>/<name>"; anything else is rejected,
// because guessing here would point a live hostname at a name that does not exist.
func (f *Fragment) ServiceTarget(resource string) (string, error) {
	kind, rest, ok := strings.Cut(resource, "/")
	if !ok || kind != "service" {
		return "", fmt.Errorf("unsupported resource %q: only service/<namespace>/<name> can be "+
			"resolved to a cluster-local name", resource)
	}
	namespace, name, ok := strings.Cut(rest, "/")
	if !ok || namespace == "" || name == "" {
		return "", fmt.Errorf("malformed resource %q: want service/<namespace>/<name>", resource)
	}
	return fmt.Sprintf("%s.%s.svc.%s", name, namespace, f.clusterDomain), nil
}

// Load returns the host -> cluster-local-name rewrites currently in the managed key. A missing
// ConfigMap or a missing key is an empty set, not an error: the key not existing yet is the
// normal first-run state.
func (f *Fragment) Load(ctx context.Context) (map[string]string, error) {
	cm, err := f.api.Get(ctx, f.name, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return map[string]string{}, nil
		}
		return nil, fmt.Errorf("get configmap %s: %w", f.name, err)
	}
	return parseRewrites(cm.Data[f.key]), nil
}

// Apply adds and removes rewrites in the managed key, writing the whole key back via server-side
// apply. It is idempotent: applying the same delta twice is a no-op, so a caller retrying after a
// partial failure converges. Removals are applied before additions, so a host appearing in both
// ends up added.
//
// It returns the rewrites the key holds afterwards, for logging.
func (f *Fragment) Apply(ctx context.Context, add map[string]string, remove []string) (map[string]string, error) {
	current, err := f.Load(ctx)
	if err != nil {
		return nil, err
	}

	desired := make(map[string]string, len(current)+len(add))
	for h, t := range current {
		desired[h] = t
	}
	for _, h := range remove {
		delete(desired, strings.ToLower(h))
	}
	for h, t := range add {
		desired[strings.ToLower(h)] = t
	}

	// Nothing to do: skip the write entirely rather than churning resourceVersion (and, through
	// it, CoreDNS reloads) on every reconcile.
	if sameRewrites(current, desired) {
		return desired, nil
	}

	cm := corev1apply.ConfigMap(f.name, "").WithData(map[string]string{f.key: render(desired)})
	if _, err := f.api.Apply(ctx, cm, metav1.ApplyOptions{FieldManager: f.fieldManager}); err != nil {
		return nil, fmt.Errorf("apply configmap %s key %s: %w", f.name, f.key, err)
	}
	return desired, nil
}

// render turns rewrites into CoreDNS directives, sorted so the rendered key is deterministic and
// a no-op reconcile produces a byte-identical value.
func render(rewrites map[string]string) string {
	hosts := make([]string, 0, len(rewrites))
	for h := range rewrites {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)

	var b strings.Builder
	b.WriteString(header)
	b.WriteString("\n")
	for _, h := range hosts {
		fmt.Fprintf(&b, "rewrite name exact %s %s\n", h, rewrites[h])
	}
	return b.String()
}

// parseRewrites extracts host -> target from "rewrite name exact <host> <target>" lines, ignoring
// blanks, comments and any directive it does not recognise. Unknown lines are dropped rather than
// preserved: this key has exactly one writer, so anything else in it is stale output from an older
// version of this code, and silently carrying it forward would make the key un-prunable.
func parseRewrites(s string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(s, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 5 {
			continue
		}
		if fields[0] != "rewrite" || fields[1] != "name" || fields[2] != "exact" {
			continue
		}
		out[strings.ToLower(fields[3])] = fields[4]
	}
	return out
}

func sameRewrites(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
