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

package coredns

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	corev1apply "k8s.io/client-go/applyconfigurations/core/v1"
)

// fakeCM is an in-memory ConfigMap. It records every Apply so tests can assert BOTH the rendered
// content and how many writes happened (write count matters: each write can trigger a CoreDNS
// reload).
type fakeCM struct {
	data      map[string]string
	notFound  bool
	applies   []map[string]string
	applyErr  error
	fieldMgrs []string
}

func (f *fakeCM) Get(_ context.Context, name string, _ metav1.GetOptions) (*corev1.ConfigMap, error) {
	if f.notFound {
		return nil, apierrors.NewNotFound(schema.GroupResource{Resource: "configmaps"}, name)
	}
	return &corev1.ConfigMap{Data: f.data}, nil
}

func (f *fakeCM) Apply(_ context.Context, cm *corev1apply.ConfigMapApplyConfiguration, opts metav1.ApplyOptions) (*corev1.ConfigMap, error) {
	if f.applyErr != nil {
		return nil, f.applyErr
	}
	f.applies = append(f.applies, cm.Data)
	f.fieldMgrs = append(f.fieldMgrs, opts.FieldManager)
	if f.data == nil {
		f.data = map[string]string{}
	}
	for k, v := range cm.Data {
		f.data[k] = v
	}
	return &corev1.ConfigMap{Data: f.data}, nil
}

func newFragment(t *testing.T, api configMapAPI) *Fragment {
	t.Helper()
	f, err := New(Config{API: api, Name: "coredns-fragments"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return f
}

func TestServiceTarget(t *testing.T) {
	f := newFragment(t, &fakeCM{})
	got, err := f.ServiceTarget("service/apps/foo")
	if err != nil {
		t.Fatalf("ServiceTarget: %v", err)
	}
	if want := "foo.apps.svc.cluster.local"; got != want {
		t.Errorf("ServiceTarget = %q, want %q", got, want)
	}

	// Anything that is not a Service must be rejected, not guessed: a wrong target would point a
	// live hostname at a name that does not exist.
	for _, bad := range []string{"ingress/apps/foo", "service/apps", "service//foo", "service/apps/", "", "foo"} {
		if _, err := f.ServiceTarget(bad); err == nil {
			t.Errorf("ServiceTarget(%q) should have failed", bad)
		}
	}
}

func TestServiceTarget_HonoursClusterDomain(t *testing.T) {
	f, err := New(Config{API: &fakeCM{}, Name: "cm", ClusterDomain: "k8s.internal"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got, _ := f.ServiceTarget("service/ns/svc")
	if want := "svc.ns.svc.k8s.internal"; got != want {
		t.Errorf("ServiceTarget = %q, want %q", got, want)
	}
}

func TestLoad_MissingConfigMapIsEmptyNotError(t *testing.T) {
	f := newFragment(t, &fakeCM{notFound: true})
	got, err := f.Load(context.Background())
	if err != nil {
		t.Fatalf("a missing ConfigMap is the normal first-run state, got error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("want empty, got %v", got)
	}
}

func TestLoad_ParsesOnlyRewriteLines(t *testing.T) {
	f := newFragment(t, &fakeCM{data: map[string]string{DefaultKey: strings.Join([]string{
		"# a comment",
		"",
		"rewrite name exact a.edns.woven a.apps.svc.cluster.local",
		"rewrite name exact B.EDNS.WOVEN b.apps.svc.cluster.local", // case-normalized
		"rewrite name prefix nope.edns.woven x",                    // not "exact"
		"forward . 1.1.1.1",                                        // unrelated directive
		"rewrite name exact malformed",                             // wrong field count
	}, "\n")}})

	got, err := f.Load(context.Background())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := map[string]string{
		"a.edns.woven": "a.apps.svc.cluster.local",
		"b.edns.woven": "b.apps.svc.cluster.local",
	}
	if len(got) != len(want) {
		t.Fatalf("parsed %v, want %v", got, want)
	}
	for h, tgt := range want {
		if got[h] != tgt {
			t.Errorf("rewrite %q = %q, want %q", h, got[h], tgt)
		}
	}
}

func TestApply_AddsAndRemoves(t *testing.T) {
	api := &fakeCM{data: map[string]string{DefaultKey: "" +
		"rewrite name exact keep.edns.woven keep.apps.svc.cluster.local\n" +
		"rewrite name exact drop.edns.woven drop.apps.svc.cluster.local\n"}}
	f := newFragment(t, api)

	got, err := f.Apply(context.Background(),
		map[string]string{"new.edns.woven": "new.apps.svc.cluster.local"},
		[]string{"drop.edns.woven"})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(got) != 2 || got["keep.edns.woven"] == "" || got["new.edns.woven"] == "" {
		t.Fatalf("resulting rewrites = %v", got)
	}
	if _, still := got["drop.edns.woven"]; still {
		t.Error("removed host is still present")
	}

	if len(api.applies) != 1 {
		t.Fatalf("want exactly 1 write, got %d", len(api.applies))
	}
	written := api.applies[0][DefaultKey]
	if !strings.Contains(written, "rewrite name exact new.edns.woven new.apps.svc.cluster.local") {
		t.Errorf("written key missing the added rewrite:\n%s", written)
	}
	if strings.Contains(written, "drop.edns.woven") {
		t.Errorf("written key still carries the removed host:\n%s", written)
	}
	if !strings.HasPrefix(written, header) {
		t.Errorf("written key must carry the do-not-edit header:\n%s", written)
	}
	// Only our own key may be written — never another owner's, and never the base Corefile.
	if len(api.applies[0]) != 1 {
		t.Errorf("Apply wrote %d keys, want exactly 1 (%s)", len(api.applies[0]), DefaultKey)
	}
	if api.fieldMgrs[0] != DefaultFieldManager {
		t.Errorf("field manager = %q, want %q", api.fieldMgrs[0], DefaultFieldManager)
	}
}

// A reconcile that changes nothing must not write. Every write bumps resourceVersion and can
// trigger a CoreDNS reload, so a no-op write is a recurring cluster-wide side effect.
func TestApply_NoChangeDoesNotWrite(t *testing.T) {
	api := &fakeCM{data: map[string]string{DefaultKey: header + "\n" +
		"rewrite name exact a.edns.woven a.apps.svc.cluster.local\n"}}
	f := newFragment(t, api)

	if _, err := f.Apply(context.Background(),
		map[string]string{"a.edns.woven": "a.apps.svc.cluster.local"}, nil); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(api.applies) != 0 {
		t.Errorf("no-op reconcile wrote %d time(s), want 0", len(api.applies))
	}
}

// Applying the same delta twice must converge, so a caller retrying after a partial failure is
// safe.
func TestApply_IsIdempotent(t *testing.T) {
	api := &fakeCM{notFound: false, data: map[string]string{}}
	f := newFragment(t, api)
	add := map[string]string{"a.edns.woven": "a.apps.svc.cluster.local"}

	first, err := f.Apply(context.Background(), add, nil)
	if err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	second, err := f.Apply(context.Background(), add, nil)
	if err != nil {
		t.Fatalf("second Apply: %v", err)
	}
	if len(first) != 1 || len(second) != 1 {
		t.Fatalf("first=%v second=%v", first, second)
	}
	if len(api.applies) != 1 {
		t.Errorf("second identical Apply wrote again (%d writes total), want 1", len(api.applies))
	}
}

// Removing a host that was never there, from a ConfigMap that does not exist, must not create the
// key just to hold a header.
func TestApply_RemoveOnlyOnEmptyDoesNotWrite(t *testing.T) {
	api := &fakeCM{notFound: true}
	f := newFragment(t, api)
	if _, err := f.Apply(context.Background(), nil, []string{"gone.edns.woven"}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(api.applies) != 0 {
		t.Errorf("wrote %d time(s) for a no-op removal, want 0", len(api.applies))
	}
}

func TestRender_IsDeterministic(t *testing.T) {
	in := map[string]string{
		"c.edns.woven": "c.apps.svc.cluster.local",
		"a.edns.woven": "a.apps.svc.cluster.local",
		"b.edns.woven": "b.apps.svc.cluster.local",
	}
	first := render(in)
	for i := 0; i < 10; i++ {
		if got := render(in); got != first {
			t.Fatalf("render is not deterministic:\n%s\nvs\n%s", first, got)
		}
	}
	// Sorted, so a diff of the live key only ever shows real changes.
	ia := strings.Index(first, "a.edns.woven")
	ib := strings.Index(first, "b.edns.woven")
	ic := strings.Index(first, "c.edns.woven")
	if ia >= ib || ib >= ic {
		t.Errorf("rewrites are not sorted:\n%s", first)
	}
}

// render output must survive parseRewrites unchanged, or the read-modify-write cycle would lose
// or duplicate entries over time.
func TestRenderParseRoundTrip(t *testing.T) {
	in := map[string]string{
		"a.edns.woven": "a.apps.svc.cluster.local",
		"b.edns.woven": "b.other.svc.cluster.local",
	}
	got := parseRewrites(render(in))
	if len(got) != len(in) {
		t.Fatalf("round trip changed the set: %v -> %v", in, got)
	}
	for h, tgt := range in {
		if got[h] != tgt {
			t.Errorf("round trip lost %q: got %q want %q", h, got[h], tgt)
		}
	}
}

func TestNew_Validates(t *testing.T) {
	if _, err := New(Config{Name: "cm"}); err == nil {
		t.Error("want error without an API client")
	}
	if _, err := New(Config{API: &fakeCM{}}); err == nil {
		t.Error("want error without a ConfigMap name")
	}
}
