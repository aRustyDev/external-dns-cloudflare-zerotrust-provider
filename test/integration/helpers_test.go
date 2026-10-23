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

//go:build integration

package integration

// Helpers for the spike tests, which exist to MEASURE what Cloudflare does rather than to assert
// what we hope it does. Their results are the lines logged as "OBSERVED ...": run them with -v and
// copy those lines into docs/multi-tunnel-lifecycle.md section 8.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/arustydev/external-dns-cloudflare-zerotrust-provider/internal/cloudflare"
)

// observe logs the outcome of a call whose answer is the point of the test. It never fails the
// test: an API that refuses is a finding, not a defect in the test.
func observe(t *testing.T, label string, err error) {
	t.Helper()
	if err == nil {
		t.Logf("OBSERVED %s: ok", label)
		return
	}
	var apiErr *cloudflare.APIError
	if errors.As(err, &apiErr) {
		t.Logf("OBSERVED %s: status=%d codes=%v message=%q", label, apiErr.StatusCode, apiErr.Codes, apiErr.Message)
		return
	}
	t.Logf("OBSERVED %s: error=%v", label, err)
}

// routesForbidden reports whether err is Cloudflare refusing the request as an authentication
// error (403, code 10000). For hostname-route writes that is what a token WITHOUT a Cloudflare One
// Networks write permission gets: the connector and tunnel permissions do not cover these routes.
func routesForbidden(err error) bool {
	var apiErr *cloudflare.APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusForbidden && cloudflare.HasCode(err, 10000)
}

// skipIfRoutesForbidden skips the test, with the reason, when err shows the token cannot write
// hostname routes. A missing permission is a problem with the environment, not with the test, so it
// must not read as a failure. Any other error is left for the caller.
func skipIfRoutesForbidden(t *testing.T, what string, err error) {
	t.Helper()
	if routesForbidden(err) {
		t.Skipf("%s: the token cannot create hostname routes (403 [10000]); it needs a Cloudflare One "+
			"Networks write permission, which connector and tunnel permissions do not grant: %v", what, err)
	}
}

// requireCreate handles the result of a FIXTURE create: it skips when the token lacks permission and
// fails on any other error.
func requireCreate(t *testing.T, what string, err error) {
	t.Helper()
	if err == nil {
		return
	}
	skipIfRoutesForbidden(t, what, err)
	t.Fatalf("%s: %v", what, err)
}

// uniqueHost returns a hostname unique to this call. testHost cannot be used when a test needs
// several, because it returns INTEGRATION_HOSTNAME verbatim whenever that is set.
func uniqueHost(t *testing.T, tag string) string {
	t.Helper()
	return fmt.Sprintf("extdns-cfzt-it-%s-%d.%s", tag, time.Now().UnixNano(), testDomainFilter(t))
}

// rawCall issues a request that the client does not expose, such as a list with filter query
// parameters or a tunnel delete, and returns the status and body without interpreting either.
func rawCall(ctx context.Context, token, method, path string, query url.Values, body string) (int, []byte, error) {
	u := cloudflare.DefaultBaseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	var rd io.Reader
	if body != "" {
		rd = bytes.NewBufferString(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return resp.StatusCode, b, err
}

// clip shortens a response body for logging.
func clip(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "..."
}
