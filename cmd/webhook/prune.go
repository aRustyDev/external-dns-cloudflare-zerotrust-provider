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

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"sigs.k8s.io/external-dns/endpoint"

	"github.com/arustydev/external-dns-cloudflare-zerotrust-provider/internal/cloudflare"
	cfprovider "github.com/arustydev/external-dns-cloudflare-zerotrust-provider/internal/provider"
)

// pruneTimeout bounds the whole run, listing and deleting together.
const pruneTimeout = 5 * time.Minute

// Exit codes for `webhook prune`.
const (
	pruneOK         = 0
	pruneFailed     = 1 // a list or a delete failed
	pruneUsageError = 2 // bad flags or missing credentials
)

const pruneUsage = `Usage: webhook prune --owner <id> [--tunnel <id>]... [--domain-filter <suffix>[,...]] [--apply]

Deletes the Cloudflare hostname routes tagged managed-by=external-dns/<id>. It exists for an owner
whose instance is gone and so cannot clean up after itself: a renamed OWNER_ID, a decommissioned
cluster, a tunnel dropped from the configuration.

It lists by default and deletes nothing until --apply is given. It only ever touches routes
carrying exactly that owner's tag; untagged routes and other owners' routes are never listed.

Only run it for an owner whose instance is no longer running. A live instance recreates anything it
still desires on its next reconcile, which is an outage window for each of those hostnames.

Needs CF_ACCOUNT_ID and CF_API_TOKEN in the environment. The token needs to be able to read, and
with --apply delete, the routes on the tunnels involved.

Exit status: 0 success (including nothing to prune), 1 a list or delete failed, 2 bad usage.

`

// pruneClient is the slice of the Cloudflare client that prune needs.
type pruneClient interface {
	ListHostnameRoutes(ctx context.Context, tunnelID string) ([]cloudflare.HostnameRoute, error)
	DeleteHostnameRoute(ctx context.Context, id string) error
}

// pruneDeps holds everything runPrune touches outside its arguments, so tests can drive it against
// a fake Cloudflare without a process, real environment variables, or the network.
type pruneDeps struct {
	getenv    func(string) string
	newClient func(accountID, apiToken string) pruneClient
	stdout    io.Writer
	stderr    io.Writer
}

// listFlag is a flag that may be repeated and also accepts comma-separated values.
type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }

func (l *listFlag) Set(v string) error {
	*l = append(*l, splitCSV(v)...)
	return nil
}

// runPrune implements `webhook prune` and returns the process exit code.
func runPrune(args []string, d pruneDeps) int {
	fs := flag.NewFlagSet("prune", flag.ContinueOnError)
	fs.SetOutput(d.stderr)
	fs.Usage = func() {
		_, _ = fmt.Fprint(d.stderr, pruneUsage)
		fs.PrintDefaults()
	}
	var tunnels listFlag
	owner := fs.String("owner", "", "owner id whose routes to delete (required)")
	fs.Var(&tunnels, "tunnel", "tunnel id to look at; repeatable or comma-separated. Omit to list the whole account")
	domainFilter := fs.String("domain-filter", "", "only routes whose hostname matches these comma-separated suffixes")
	apply := fs.Bool("apply", false, "actually delete the routes; without it this only lists them")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return pruneOK
		}
		return pruneUsageError
	}
	if fs.NArg() > 0 {
		_, _ = fmt.Fprintf(d.stderr, "prune: unexpected argument %q\n", fs.Arg(0))
		return pruneUsageError
	}
	ownerID := strings.TrimSpace(*owner)
	if ownerID == "" {
		_, _ = fmt.Fprintln(d.stderr, "prune: --owner is required")
		return pruneUsageError
	}
	accountID, token := d.getenv("CF_ACCOUNT_ID"), d.getenv("CF_API_TOKEN")
	if accountID == "" || token == "" {
		_, _ = fmt.Fprintln(d.stderr, "prune: CF_ACCOUNT_ID and CF_API_TOKEN must be set")
		return pruneUsageError
	}

	client := d.newClient(accountID, token)
	ctx, cancel := context.WithTimeout(context.Background(), pruneTimeout)
	defer cancel()
	filter := endpoint.NewDomainFilter(splitCSV(*domainFilter))

	// A blank tunnel id lists the whole account, which is what an owner with no known tunnels needs.
	scopes := []string(tunnels)
	if len(scopes) == 0 {
		scopes = []string{""}
	}
	seen := map[string]struct{}{}
	var found []cloudflare.HostnameRoute
	for _, tid := range scopes {
		routes, err := client.ListHostnameRoutes(ctx, tid)
		if err != nil {
			_, _ = fmt.Fprintf(d.stderr, "prune: list routes (tunnel %q): %v\n", tid, err)
			return pruneFailed
		}
		for _, r := range routes {
			if r.DeletedAt != nil || !cfprovider.RouteTaggedBy(r.Comment, ownerID) || !filter.Match(r.Hostname) {
				continue
			}
			if _, dup := seen[r.ID]; dup {
				continue
			}
			seen[r.ID] = struct{}{}
			found = append(found, r)
		}
	}
	sort.Slice(found, func(i, j int) bool {
		if found[i].Hostname != found[j].Hostname {
			return found[i].Hostname < found[j].Hostname
		}
		return found[i].ID < found[j].ID
	})

	where := "the whole account"
	if len(tunnels) > 0 {
		where = "tunnel " + strings.Join(tunnels, ", ")
	}
	_, _ = fmt.Fprintf(d.stdout, "Routes tagged managed-by=external-dns/%s on %s:\n", ownerID, where)
	if len(found) == 0 {
		_, _ = fmt.Fprintln(d.stdout, "Nothing to prune.")
		return pruneOK
	}
	tw := tabwriter.NewWriter(d.stdout, 0, 8, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "HOSTNAME\tTUNNEL\tROUTE_ID")
	for _, r := range found {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\n", r.Hostname, r.TunnelID, r.ID)
	}
	_ = tw.Flush()

	if !*apply {
		_, _ = fmt.Fprintf(d.stdout, "\nDry run: nothing was deleted. Re-run with --apply to delete these %d routes.\n", len(found))
		return pruneOK
	}

	failures := 0
	for _, r := range found {
		if err := client.DeleteHostnameRoute(ctx, r.ID); err != nil {
			failures++
			_, _ = fmt.Fprintf(d.stderr, "FAILED   %s (%s): %v\n", r.Hostname, r.ID, err)
			continue
		}
		_, _ = fmt.Fprintf(d.stdout, "deleted  %s (%s)\n", r.Hostname, r.ID)
	}
	_, _ = fmt.Fprintf(d.stdout, "\nDeleted %d of %d routes.\n", len(found)-failures, len(found))
	if failures > 0 {
		return pruneFailed
	}
	return pruneOK
}
