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

import { parsePolicy } from "../src/policy.ts";

// Shared by handler.test.ts and serve.ts, the small server the Go end-to-end test talks to.

export const ACCOUNT = "acct1";
export const SECRET = "UPSTREAM-ACCOUNT-TOKEN";
export const TA = "aaaaaaaa-0000-0000-0000-00000000000a"; // client x
export const TB = "bbbbbbbb-0000-0000-0000-00000000000b"; // client y
export const TB2 = "bbbbbbbb-0000-0000-0000-0000000000b2"; // client y, a second tunnel
export const TC = "cccccccc-0000-0000-0000-00000000000c"; // nobody's

export const POLICY = parsePolicy(
  JSON.stringify({
    x: { owner: "cluster-x", tunnels: [TA], suffixes: ["x.woven", "shared.woven"] },
    y: { owner: "cluster-y", tunnels: [TB, TB2], suffixes: ["y.woven", "shared.woven"] },
    open: { tunnels: ["dddddddd-0000-0000-0000-00000000000d"], suffixes: ["open.woven"] },
  }),
);

export interface Route {
  id: string;
  hostname: string;
  tunnel_id: string;
  comment?: string;
}

export interface Call {
  method: string;
  path: string;
  query: URLSearchParams;
  body: unknown;
  authorization: string | null;
}

export const tag = (owner: string) => `managed-by=external-dns/${owner}`;

/** A fake Cloudflare hostname-routes API with the behavior measured on 2026-10-23. */
export function fakeCloudflare(initial: Route[]) {
  const routes = [...initial];
  const calls: Call[] = [];
  let next = 1000;
  const base = `/accounts/${ACCOUNT}/zerotrust/routes/hostname`;
  const envelope = (status: number, body: unknown) =>
    new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  const fail = (status: number, code: number, message: string) =>
    envelope(status, { success: false, errors: [{ code, message }], messages: [], result: null });

  const impl = (async (input: string, init?: RequestInit) => {
    const url = new URL(input);
    const headers = new Headers(init?.headers);
    const body = init?.body ? JSON.parse(init.body as string) : undefined;
    const path = url.pathname.replace("/client/v4", "");
    calls.push({
      method: init?.method ?? "GET",
      path,
      query: url.searchParams,
      body,
      authorization: headers.get("authorization"),
    });
    if (headers.get("authorization") !== `Bearer ${SECRET}`) return fail(403, 10000, "Authentication error");
    const method = init?.method ?? "GET";

    if (path === base && method === "GET") {
      const q = url.searchParams;
      let found = routes.filter(
        (r) =>
          (q.get("tunnel_id") === null || r.tunnel_id === q.get("tunnel_id")) &&
          (q.get("hostname") === null || r.hostname === q.get("hostname")) &&
          (q.get("comment") === null || r.comment === q.get("comment")),
      );
      const perPage = Number(q.get("per_page") ?? 20);
      const page = Number(q.get("page") ?? 1);
      const total = found.length;
      found = found.slice((page - 1) * perPage, page * perPage);
      return envelope(200, {
        success: true,
        errors: [],
        messages: [],
        result: found,
        result_info: { page, per_page: perPage, count: found.length, total_count: total },
      });
    }
    if (path === base && method === "POST") {
      const b = body as Route;
      const stored = b.hostname.replace(/^\*\./, "");
      if (routes.some((r) => r.hostname === stored)) {
        return fail(409, 1108, "Hostname Route already routed to another tunnel");
      }
      const route = { id: `ffffffff-0000-0000-0000-${String(next++).padStart(12, "0")}`, hostname: stored, tunnel_id: b.tunnel_id, comment: b.comment };
      routes.push(route);
      return envelope(200, { success: true, errors: [], messages: [], result: route });
    }
    const item = path.startsWith(`${base}/`) ? path.slice(base.length + 1) : null;
    if (item !== null) {
      const at = routes.findIndex((r) => r.id === item);
      if (at < 0) return fail(404, 1107, "Hostname Route not found");
      if (method === "GET") return envelope(200, { success: true, errors: [], messages: [], result: routes[at] });
      if (method === "PATCH") {
        routes[at] = { ...routes[at], ...(body as object) };
        return envelope(200, { success: true, errors: [], messages: [], result: routes[at] });
      }
      if (method === "DELETE") {
        const [gone] = routes.splice(at, 1);
        return envelope(200, { success: true, errors: [], messages: [], result: { id: gone.id } });
      }
    }
    return fail(404, 7003, "No route for the URI");
  }) as unknown as typeof fetch;

  return { impl, calls, routes, mutations: () => calls.filter((c) => c.method !== "GET") };
}

/** The routes every test starts from: two clients' own routes, one held by both, and an orphan. */
export function initialRoutes(): Route[] {
  return [
    { id: "a1a1a1a1-0000-0000-0000-000000000001", hostname: "foo.x.woven", tunnel_id: TA, comment: tag("cluster-x") },
    { id: "b1b1b1b1-0000-0000-0000-000000000001", hostname: "bar.y.woven", tunnel_id: TB, comment: tag("cluster-y") },
    { id: "b2b2b2b2-0000-0000-0000-000000000002", hostname: "held.shared.woven", tunnel_id: TB, comment: tag("cluster-y") },
    { id: "c1c1c1c1-0000-0000-0000-000000000001", hostname: "orphan.other.woven", tunnel_id: TC, comment: "someone else" },
  ];
}
