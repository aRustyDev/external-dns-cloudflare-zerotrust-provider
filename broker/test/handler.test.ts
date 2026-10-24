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

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { createHandler } from "../src/handler.ts";
import {
  ACCOUNT,
  POLICY,
  SECRET,
  TA,
  TB,
  TB2,
  TC,
  fakeCloudflare,
  initialRoutes,
  tag,
  type Route,
} from "./support.ts";

function world(extra: Route[] = [], authenticate?: (client: string | null) => boolean) {
  const upstream = fakeCloudflare([...initialRoutes(), ...extra]);
  const logs: Array<Record<string, unknown>> = [];
  const handle = createHandler({
    policy: POLICY,
    accountId: ACCOUNT,
    upstreamBase: "https://upstream.test/client/v4",
    upstreamToken: SECRET,
    authenticate: async (req) => {
      const client = req.headers.get("x-test-client");
      if (client === null) return null;
      if (authenticate !== undefined && !authenticate(client)) return null;
      return { clientId: client };
    },
    fetch: upstream.impl,
    log: (line) => logs.push(line),
  });

  const call = (
    method: string,
    path: string,
    opts: { client?: string | null; body?: unknown; rawBody?: string; query?: Record<string, string> } = {},
  ) => {
    const url = new URL(`https://broker.test${path}`);
    for (const [k, v] of Object.entries(opts.query ?? {})) url.searchParams.set(k, v);
    const headers: Record<string, string> = { "content-type": "application/json" };
    const client = opts.client === undefined ? "x" : opts.client;
    if (client !== null) headers["x-test-client"] = client;
    const body = opts.rawBody ?? (opts.body === undefined ? undefined : JSON.stringify(opts.body));
    return handle(new Request(url, { method, headers, body }));
  };
  return { call, upstream, logs };
}

const routes = `/accounts/${ACCOUNT}/zerotrust/routes/hostname`;
const json = async (res: Response) => JSON.parse(await res.text());

describe("authentication", () => {
  it("answers 401 with Cloudflare's envelope when there is no identity, and calls nothing upstream", async () => {
    const w = world();
    const res = await w.call("GET", routes, { client: null });
    assert.equal(res.status, 401);
    const body = await json(res);
    assert.equal(body.success, false);
    assert.equal(body.errors[0].code, 10000);
    assert.equal(w.upstream.calls.length, 0);
  });

  it("answers 403 for an authenticated client that is not in the policy, without a hint why", async () => {
    const w = world();
    const res = await w.call("GET", routes, { client: "stranger" });
    assert.equal(res.status, 403);
    assert.equal(w.upstream.calls.length, 0);
    assert.doesNotMatch(await res.text(), /policy|x\b|cluster/i);
  });

  it("answers 404 for a path outside the hostname-routes API or for another account", async () => {
    const w = world();
    assert.equal((await w.call("GET", "/accounts/acct1/tunnels")).status, 404);
    assert.equal((await w.call("GET", "/accounts/other/zerotrust/routes/hostname")).status, 404);
    assert.equal((await w.call("GET", "/")).status, 404);
    assert.equal(w.upstream.calls.length, 0);
  });

  it("accepts Cloudflare's /client/v4 prefix", async () => {
    const w = world();
    const res = await w.call("GET", `/client/v4${routes}`);
    assert.equal(res.status, 200);
  });

  it("answers 405 for a method the broker does not serve, after authenticating", async () => {
    const w = world();
    assert.equal((await w.call("PUT", routes)).status, 405);
    assert.equal((await w.call("GET", `${routes}/a1a1a1a1-0000-0000-0000-000000000001`)).status, 405);
    assert.equal((await w.call("DELETE", routes)).status, 405);
    assert.equal(w.upstream.calls.length, 0);
  });
});

describe("list", () => {
  it("returns only the client's own tunnels' routes, in Cloudflare's envelope", async () => {
    const w = world();
    const res = await w.call("GET", routes);
    assert.equal(res.status, 200);
    const body = await json(res);
    assert.equal(body.success, true);
    assert.deepEqual(body.errors, []);
    assert.deepEqual(
      body.result.map((r: Route) => r.hostname),
      ["foo.x.woven"],
    );
    assert.deepEqual(body.result_info, { page: 1, per_page: 100, count: 1, total_count: 1 });
    // Every upstream list was pinned to a tunnel the client holds.
    for (const c of w.upstream.calls) assert.equal(c.query.get("tunnel_id"), TA);
  });

  it("merges all of a multi-tunnel client's tunnels", async () => {
    const w = world();
    const body = await json(await w.call("GET", routes, { client: "y" }));
    assert.deepEqual(body.result.map((r: Route) => r.hostname).sort(), ["bar.y.woven", "held.shared.woven"]);
    assert.deepEqual(new Set(w.upstream.calls.map((c) => c.query.get("tunnel_id"))), new Set([TB, TB2]));
  });

  it("refuses to list a tunnel the client does not hold, without asking upstream", async () => {
    const w = world();
    const res = await w.call("GET", routes, { query: { tunnel_id: TB } });
    assert.equal(res.status, 403);
    assert.equal(w.upstream.calls.length, 0);
  });

  it("lists a named tunnel the client does hold", async () => {
    const w = world();
    const body = await json(await w.call("GET", routes, { query: { tunnel_id: TA.toUpperCase() } }));
    assert.equal(body.result.length, 1);
  });

  it("reveals nothing about another client's hostname through a hostname filter", async () => {
    const w = world();
    const foreign = await json(await w.call("GET", routes, { query: { hostname: "bar.y.woven" } }));
    assert.deepEqual(foreign.result, []);
    assert.equal(foreign.result_info.total_count, 0);
    const own = await json(await w.call("GET", routes, { query: { hostname: "foo.x.woven" } }));
    assert.equal(own.result.length, 1);
    // The filter could not widen the search beyond the client's tunnel.
    for (const c of w.upstream.calls) assert.equal(c.query.get("tunnel_id"), TA);
  });

  it("forwards only the filters it knows", async () => {
    const w = world();
    await w.call("GET", routes, { query: { hostname: "foo.x.woven", evil: "1", tunnel_id: TA } });
    for (const c of w.upstream.calls) assert.equal(c.query.get("evil"), null);
  });

  it("follows upstream pages and returns one complete page", async () => {
    const many: Route[] = [];
    for (let i = 0; i < 250; i++) {
      many.push({ id: `m${i}`, hostname: `h${i}.x.woven`, tunnel_id: TA, comment: tag("cluster-x") });
    }
    const w = world(many);
    const body = await json(await w.call("GET", routes));
    assert.equal(body.result.length, 251); // the 250 plus foo.x.woven
    assert.ok(body.result_info.per_page >= body.result_info.total_count);
    assert.ok(w.upstream.calls.length >= 3);
  });

  it("passes an upstream failure through and does not invent a result", async () => {
    const w = world();
    const failing = createHandler({
      policy: POLICY,
      accountId: ACCOUNT,
      upstreamBase: "https://upstream.test/client/v4",
      upstreamToken: SECRET,
      authenticate: async () => ({ clientId: "x" }),
      fetch: (async () => new Response('{"success":false}', { status: 500 })) as unknown as typeof fetch,
      log: () => {},
    });
    const res = await failing(new Request(`https://broker.test${routes}`));
    assert.equal(res.status, 500);
    assert.ok(w); // keep the shared world referenced
  });

  it("answers 502 when upstream returns something that is not JSON", async () => {
    const odd = createHandler({
      policy: POLICY,
      accountId: ACCOUNT,
      upstreamBase: "https://upstream.test/client/v4",
      upstreamToken: SECRET,
      authenticate: async () => ({ clientId: "x" }),
      fetch: (async () => new Response("<html>", { status: 200 })) as unknown as typeof fetch,
      log: () => {},
    });
    assert.equal((await odd(new Request(`https://broker.test${routes}`))).status, 502);
  });

  // MEASURED in workerd (wrangler dev) on 2026-10-24: `{ fetch }.fetch(url)` throws "Illegal
  // invocation: function called with incorrect `this` reference", while `const f = fetch; f(url)`
  // works. Node accepts both, so the first deployed broker answered every request with error 1101.
  it("calls fetch detached, because the Workers runtime refuses it as a method of another object", async () => {
    const runtimeFetch = function (this: unknown): Promise<Response> {
      if (this !== undefined && this !== globalThis) throw new TypeError("Illegal invocation");
      const page = { page: 1, per_page: 100, count: 0, total_count: 0 };
      return Promise.resolve(new Response(JSON.stringify({ success: true, result: [], result_info: page })));
    };
    const handle = createHandler({
      policy: POLICY,
      accountId: ACCOUNT,
      upstreamBase: "https://upstream.test/client/v4",
      upstreamToken: SECRET,
      authenticate: async () => ({ clientId: "x" }),
      fetch: runtimeFetch as unknown as typeof fetch,
      log: () => {},
    });
    assert.equal((await handle(new Request(`https://broker.test${routes}`))).status, 200);
  });
});

describe("create", () => {
  const good = { hostname: "new.x.woven", tunnel_id: TA, comment: tag("cluster-x") };

  it("creates a route in the client's own space and sends upstream only the three known fields", async () => {
    const w = world();
    const res = await w.call("POST", routes, { body: { ...good, evil: "x", id: "forced" } });
    assert.equal(res.status, 200);
    const sent = w.upstream.mutations();
    assert.equal(sent.length, 1);
    assert.deepEqual(sent[0].body, good);
    // The caller's request never carried the account token, and upstream got it only from the broker.
    assert.equal(sent[0].authorization, `Bearer ${SECRET}`);
    assert.doesNotMatch(await res.text(), new RegExp(SECRET));
  });

  for (const [name, body] of [
    ["a tunnel the client does not hold", { ...good, tunnel_id: TB }],
    ["a hostname outside the client's suffixes", { ...good, hostname: "new.y.woven" }],
    ["a hostname that only ends the same way", { ...good, hostname: "newx.woven" }],
    ["another owner's tag", { ...good, comment: tag("cluster-y") }],
    ["no comment at all", { hostname: good.hostname, tunnel_id: TA }],
    ["a tunnel that is not a string", { ...good, tunnel_id: [TA] }],
  ] as Array<[string, Record<string, unknown>]>) {
    it(`refuses ${name} and never reaches upstream`, async () => {
      const w = world();
      const res = await w.call("POST", routes, { body });
      assert.equal(res.status, 403);
      assert.equal((await json(res)).errors[0].code, 9109);
      assert.equal(w.upstream.calls.length, 0);
    });
  }

  it("refuses a body that is not a JSON object, or is too large", async () => {
    const w = world();
    assert.equal((await w.call("POST", routes, { rawBody: "{nope" })).status, 400);
    assert.equal((await w.call("POST", routes, { rawBody: "[]" })).status, 400);
    assert.equal((await w.call("POST", routes, { rawBody: JSON.stringify({ ...good, comment: "c".repeat(70_000) }) })).status, 400);
    assert.equal(w.upstream.calls.length, 0);
  });

  it("checks a wildcard by its stored form", async () => {
    const w = world();
    assert.equal((await w.call("POST", routes, { body: { ...good, hostname: "*.wild.x.woven" } })).status, 200);
    assert.equal((await w.call("POST", routes, { body: { ...good, hostname: "*.wild.y.woven" } })).status, 403);
  });

  it("lets a client with no owner write any comment", async () => {
    const w = world();
    const body = { hostname: "a.open.woven", tunnel_id: "dddddddd-0000-0000-0000-00000000000d", comment: "free text" };
    assert.equal((await w.call("POST", routes, { client: "open", body })).status, 200);
  });

  // The conflict signal. Cloudflare's 409 / 1108 says the hostname is taken and nothing else, and
  // the broker must not add to it: no tunnel, no route id, no other client's name.
  it("passes a conflict with another client's route through as Cloudflare's own 409 / 1108", async () => {
    const w = world();
    const res = await w.call("POST", routes, { body: { hostname: "held.shared.woven", tunnel_id: TA, comment: tag("cluster-x") } });
    assert.equal(res.status, 409);
    const text = await res.text();
    assert.equal(JSON.parse(text).errors[0].code, 1108);
    for (const leaked of [TB, TB2, "b2b2b2b2-0000-0000-0000-000000000002", "cluster-y", "bar.y.woven"]) {
      assert.ok(!text.includes(leaked), `the conflict response leaked ${leaked}`);
    }
  });
});

describe("patch", () => {
  it("rewrites the comment of the client's own route", async () => {
    const w = world();
    const res = await w.call("PATCH", `${routes}/a1a1a1a1-0000-0000-0000-000000000001`, { body: { comment: tag("cluster-x"), evil: 1 } });
    assert.equal(res.status, 200);
    const sent = w.upstream.mutations();
    assert.equal(sent.length, 1);
    assert.deepEqual(sent[0].body, { comment: tag("cluster-x") });
  });

  it("retargets between the client's own tunnels", async () => {
    const w = world();
    const body = { hostname: "bar.y.woven", tunnel_id: TB2, comment: tag("cluster-y") };
    assert.equal((await w.call("PATCH", `${routes}/b1b1b1b1-0000-0000-0000-000000000001`, { client: "y", body })).status, 200);
    assert.equal(w.upstream.routes.find((r) => r.id === "b1b1b1b1-0000-0000-0000-000000000001")?.tunnel_id, TB2);
  });

  it("refuses to move a route onto another client's tunnel, and does not patch", async () => {
    const w = world();
    const res = await w.call("PATCH", `${routes}/a1a1a1a1-0000-0000-0000-000000000001`, { body: { tunnel_id: TB } });
    assert.equal(res.status, 403);
    assert.equal(w.upstream.mutations().length, 0);
  });

  it("refuses to rename a route outside the client's suffixes, or to write another owner's tag", async () => {
    const w = world();
    assert.equal((await w.call("PATCH", `${routes}/a1a1a1a1-0000-0000-0000-000000000001`, { body: { hostname: "foo.y.woven" } })).status, 403);
    assert.equal((await w.call("PATCH", `${routes}/a1a1a1a1-0000-0000-0000-000000000001`, { body: { comment: tag("cluster-y") } })).status, 403);
    assert.equal(w.upstream.mutations().length, 0);
  });

  // The redaction rule: a route that is not the client's looks exactly like one that does not exist.
  it("answers a foreign route exactly as it answers an unknown id", async () => {
    const w = world();
    const foreign = await w.call("PATCH", `${routes}/b1b1b1b1-0000-0000-0000-000000000001`, { body: { comment: tag("cluster-x") } });
    const unknown = await w.call("PATCH", `${routes}/deadbeef-0000-0000-0000-000000000000`, { body: { comment: tag("cluster-x") } });
    assert.equal(foreign.status, 404);
    assert.equal(unknown.status, 404);
    assert.deepEqual(await json(foreign), await json(unknown));
    assert.equal(w.upstream.mutations().length, 0);
  });

  it("treats a route on the client's tunnel but outside its suffixes as not found", async () => {
    const w = world([{ id: "a9a9a9a9-0000-0000-0000-000000000009", hostname: "stray.y.woven", tunnel_id: TA, comment: "x" }]);
    assert.equal((await w.call("PATCH", `${routes}/a9a9a9a9-0000-0000-0000-000000000009`, { body: { comment: tag("cluster-x") } })).status, 404);
    assert.equal(w.upstream.mutations().length, 0);
  });

  it("refuses a body that is not a JSON object", async () => {
    const w = world();
    assert.equal((await w.call("PATCH", `${routes}/a1a1a1a1-0000-0000-0000-000000000001`, { rawBody: "nope" })).status, 400);
  });
});

describe("delete", () => {
  it("deletes the client's own route", async () => {
    const w = world();
    assert.equal((await w.call("DELETE", `${routes}/a1a1a1a1-0000-0000-0000-000000000001`)).status, 200);
    assert.deepEqual(w.upstream.mutations().map((c) => [c.method, c.path.split("/").pop()]), [["DELETE", "a1a1a1a1-0000-0000-0000-000000000001"]]);
    assert.ok(!w.upstream.routes.some((r) => r.id === "a1a1a1a1-0000-0000-0000-000000000001"));
  });

  it("answers a foreign route exactly as an unknown id, and deletes nothing", async () => {
    const w = world();
    const foreign = await w.call("DELETE", `${routes}/b1b1b1b1-0000-0000-0000-000000000001`);
    const unknown = await w.call("DELETE", `${routes}/deadbeef-0000-0000-0000-000000000000`);
    assert.equal(foreign.status, 404);
    assert.deepEqual(await json(foreign), await json(unknown));
    assert.equal(w.upstream.mutations().length, 0);
    assert.ok(w.upstream.routes.some((r) => r.id === "b1b1b1b1-0000-0000-0000-000000000001"));
  });

  it("deletes the route of a tunnel nobody holds for nobody", async () => {
    const w = world();
    assert.equal((await w.call("DELETE", `${routes}/c1c1c1c1-0000-0000-0000-000000000001`)).status, 404);
    assert.equal(w.upstream.mutations().length, 0);
  });

  it("rejects an id that is not an id without asking upstream", async () => {
    const w = world();
    for (const bad of ["..%2Fx", "a", "has space", "%00"]) {
      assert.equal((await w.call("DELETE", `${routes}/${bad}`)).status, 404, bad);
    }
    assert.equal(w.upstream.calls.length, 0);
  });
});

describe("audit log", () => {
  it("records one line for each authenticated decision and never a secret", async () => {
    const w = world();
    await w.call("GET", routes);
    await w.call("POST", routes, { body: { hostname: "new.x.woven", tunnel_id: TB, comment: tag("cluster-x") } });
    await w.call("DELETE", `${routes}/b1b1b1b1-0000-0000-0000-000000000001`);
    await w.call("GET", routes, { client: null });
    await w.call("GET", routes, { client: "stranger" });

    assert.deepEqual(
      w.logs.map((l) => [l.event, l.op ?? null, l.status ?? null]),
      [
        ["allowed", "list", 200],
        ["refused", "create", 403],
        ["refused", "delete", 404],
        ["denied", null, null],
        ["denied", null, null],
      ],
    );
    const text = JSON.stringify(w.logs);
    assert.ok(!text.includes(SECRET), "the account token appeared in the log");
    assert.ok(!text.includes("authorization"), "a header appeared in the log");
  });
});
