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

// The broker. It speaks Cloudflare's own hostname-routes API, at the same paths and with the same
// response envelope, so the provider's existing client can point at it unchanged. In between it
// applies a per-client policy, so one instance can neither see nor touch another's routes while
// the account-wide token stays here and never reaches a cluster.

import {
  commentAllowed,
  hostnameAllowed,
  tunnelAllowed,
  type ClientPolicy,
  type Policy,
} from "./policy.ts";
import type { Identity } from "./access.ts";

export interface Deps {
  policy: Policy;
  accountId: string;
  /** Cloudflare's API root, "https://api.cloudflare.com/client/v4". */
  upstreamBase: string;
  /** The account-wide token. It is only ever sent upstream and never returned or logged. */
  upstreamToken: string;
  /** Returns the caller's identity, or null when the request is not authenticated. */
  authenticate: (request: Request) => Promise<Identity | null>;
  /** Used for every upstream call. */
  fetch: typeof fetch;
  /** Receives one structured line per decision. It must not be given secrets. */
  log: (line: Record<string, unknown>) => void;
}

interface Route {
  id?: string;
  hostname?: string;
  tunnel_id?: string;
  comment?: string;
}

// Error codes in Cloudflare's envelope. 9109 is what Cloudflare itself returns for "unauthorized to
// access the requested resource"; 1107 is its "Hostname Route not found".
const CODE_UNAUTHENTICATED = 10000;
const CODE_DENIED = 9109;
const CODE_NOT_FOUND = 1107;

const MAX_BODY_BYTES = 64 * 1024;
const MAX_UPSTREAM_PAGES = 100;
const ID_PATTERN = /^[0-9a-fA-F-]{8,64}$/;
const JSON_HEADERS = { "content-type": "application/json" };

function errorResponse(status: number, code: number, message: string): Response {
  return new Response(
    JSON.stringify({ success: false, errors: [{ code, message }], messages: [], result: null }),
    { status, headers: JSON_HEADERS },
  );
}

/** The same response for a route that is not the caller's and one that does not exist. */
function notFound(): Response {
  return errorResponse(404, CODE_NOT_FOUND, "Hostname Route not found");
}

function passthrough(status: number, body: string): Response {
  return new Response(body, { status, headers: JSON_HEADERS });
}

type Target = { kind: "collection" } | { kind: "item"; id: string };

/** Accepts Cloudflare's paths, with or without its /client/v4 prefix, for this account only. */
function parseTarget(pathname: string, accountId: string): Target | null {
  let path = pathname.replace(/\/+$/, "");
  if (path.startsWith("/client/v4")) path = path.slice("/client/v4".length);
  const m = /^\/accounts\/([^/]+)\/zerotrust\/routes\/hostname(?:\/([^/]+))?$/.exec(path);
  if (m === null || m[1] !== accountId) return null;
  return m[2] === undefined ? { kind: "collection" } : { kind: "item", id: m[2] };
}

async function readJsonObject(request: Request): Promise<Record<string, unknown> | null> {
  const text = await request.text();
  if (text.length > MAX_BODY_BYTES) return null;
  try {
    const value: unknown = JSON.parse(text);
    return typeof value === "object" && value !== null && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

/** Keeps only the named keys that are present, so an extra field can never reach Cloudflare. */
function pick(body: Record<string, unknown>, keys: string[]): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const key of keys) if (body[key] !== undefined) out[key] = body[key];
  return out;
}

export function createHandler(deps: Deps): (request: Request) => Promise<Response> {
  const routesUrl = `${deps.upstreamBase}/accounts/${deps.accountId}/zerotrust/routes/hostname`;
  const upstreamHeaders = {
    authorization: `Bearer ${deps.upstreamToken}`,
    "content-type": "application/json",
  };

  // Called detached on purpose: the Workers runtime throws "Illegal invocation" when fetch is called
  // as a method of another object (deps.fetch(...)), which Node does not, so only a test that mimics
  // the runtime's check can notice.
  const send = deps.fetch;

  async function upstream(method: string, url: string, body?: unknown): Promise<Response> {
    return send(url, {
      method,
      headers: upstreamHeaders,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  }

  /** Looks a route up by id upstream. Returns it only if it is the client's own. */
  async function ownRoute(
    client: ClientPolicy,
    id: string,
  ): Promise<{ ok: true; route: Route } | { ok: false; response: Response }> {
    if (!ID_PATTERN.test(id)) return { ok: false, response: notFound() };
    const res = await upstream("GET", `${routesUrl}/${encodeURIComponent(id)}`);
    const text = await res.text();
    if (!res.ok) return { ok: false, response: passthrough(res.status, text) };
    let route: Route;
    try {
      route = ((JSON.parse(text) as { result?: Route }).result ?? {}) as Route;
    } catch {
      return { ok: false, response: errorResponse(502, 1000, "unexpected response from Cloudflare") };
    }
    // A route on a tunnel the client does not hold, or under a hostname it does not manage, is
    // answered exactly like a route that does not exist, so ids cannot be probed.
    if (!tunnelAllowed(client, route.tunnel_id) || !hostnameAllowed(client, route.hostname)) {
      return { ok: false, response: notFound() };
    }
    return { ok: true, route };
  }

  async function list(client: ClientPolicy, request: Request): Promise<{ response: Response; tunnel?: string }> {
    const params = new URL(request.url).searchParams;
    const requested = params.get("tunnel_id");
    if (requested !== null && !tunnelAllowed(client, requested)) {
      return {
        response: errorResponse(403, CODE_DENIED, "this client may not list that tunnel"),
        tunnel: requested,
      };
    }
    // With no tunnel named, list every tunnel the client holds and nothing else. That is the
    // redaction: an account-wide list through the broker is the client's own routes.
    const tunnels = requested !== null ? [requested.trim().toLowerCase()] : client.tunnels;

    const filters = new URLSearchParams();
    for (const key of ["hostname", "comment", "is_deleted"]) {
      const value = params.get(key);
      if (value !== null) filters.set(key, value);
    }

    const routes: Route[] = [];
    for (const tunnel of tunnels) {
      for (let page = 1; page <= MAX_UPSTREAM_PAGES; page++) {
        const query = new URLSearchParams(filters);
        query.set("tunnel_id", tunnel);
        query.set("page", String(page));
        query.set("per_page", "100");
        const res = await upstream("GET", `${routesUrl}?${query}`);
        const text = await res.text();
        if (!res.ok) return { response: passthrough(res.status, text) };
        let body: { result?: Route[]; result_info?: { per_page?: number; total_count?: number } };
        try {
          body = JSON.parse(text);
        } catch {
          return { response: errorResponse(502, 1000, "unexpected response from Cloudflare") };
        }
        const batch = body.result ?? [];
        routes.push(...batch.filter((r) => tunnelAllowed(client, r.tunnel_id)));
        const info = body.result_info;
        if (batch.length === 0 || !info?.per_page || page * info.per_page >= (info.total_count ?? 0)) break;
      }
    }

    // One page holding everything, so a client that follows result_info stops after this response.
    const perPage = Math.max(100, routes.length);
    return {
      response: new Response(
        JSON.stringify({
          success: true,
          errors: [],
          messages: [],
          result: routes,
          result_info: { page: 1, per_page: perPage, count: routes.length, total_count: routes.length },
        }),
        { status: 200, headers: JSON_HEADERS },
      ),
    };
  }

  async function create(client: ClientPolicy, request: Request): Promise<{ response: Response; hostname?: string; tunnel?: string }> {
    const body = await readJsonObject(request);
    if (body === null) return { response: errorResponse(400, 1000, "the request body must be a JSON object") };
    const hostname = typeof body.hostname === "string" ? body.hostname : undefined;
    const tunnel = typeof body.tunnel_id === "string" ? body.tunnel_id : undefined;
    const seen = { hostname, tunnel };

    if (!tunnelAllowed(client, body.tunnel_id)) {
      return { response: errorResponse(403, CODE_DENIED, "this client may not create routes on that tunnel"), ...seen };
    }
    if (!hostnameAllowed(client, body.hostname)) {
      return {
        response: errorResponse(403, CODE_DENIED, "that hostname is outside the suffixes this client may manage"),
        ...seen,
      };
    }
    if (!commentAllowed(client, body.comment, true)) {
      return { response: errorResponse(403, CODE_DENIED, "the comment must carry this client's owner tag"), ...seen };
    }
    // A conflict with a route held elsewhere comes back as Cloudflare's own 409 / 1108, which says
    // only that the hostname is taken. It is passed through untouched.
    const res = await upstream("POST", routesUrl, pick(body, ["hostname", "tunnel_id", "comment"]));
    return { response: passthrough(res.status, await res.text()), ...seen };
  }

  async function patch(client: ClientPolicy, id: string, request: Request): Promise<{ response: Response; hostname?: string; tunnel?: string }> {
    const body = await readJsonObject(request);
    if (body === null) return { response: errorResponse(400, 1000, "the request body must be a JSON object") };

    const found = await ownRoute(client, id);
    if (!found.ok) return { response: found.response };
    const seen = { hostname: found.route.hostname, tunnel: found.route.tunnel_id };

    if (body.tunnel_id !== undefined && !tunnelAllowed(client, body.tunnel_id)) {
      return { response: errorResponse(403, CODE_DENIED, "this client may not move routes to that tunnel"), ...seen };
    }
    if (body.hostname !== undefined && !hostnameAllowed(client, body.hostname)) {
      return {
        response: errorResponse(403, CODE_DENIED, "that hostname is outside the suffixes this client may manage"),
        ...seen,
      };
    }
    if (!commentAllowed(client, body.comment, false)) {
      return { response: errorResponse(403, CODE_DENIED, "the comment must carry this client's owner tag"), ...seen };
    }
    const res = await upstream("PATCH", `${routesUrl}/${encodeURIComponent(id)}`, pick(body, ["hostname", "tunnel_id", "comment"]));
    return { response: passthrough(res.status, await res.text()), ...seen };
  }

  async function remove(client: ClientPolicy, id: string): Promise<{ response: Response; hostname?: string; tunnel?: string }> {
    const found = await ownRoute(client, id);
    if (!found.ok) return { response: found.response };
    const res = await upstream("DELETE", `${routesUrl}/${encodeURIComponent(id)}`);
    return {
      response: passthrough(res.status, await res.text()),
      hostname: found.route.hostname,
      tunnel: found.route.tunnel_id,
    };
  }

  return async function handle(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const target = parseTarget(url.pathname, deps.accountId);
    if (target === null) return notFound();

    const identity = await deps.authenticate(request);
    if (identity === null) {
      deps.log({ event: "denied", reason: "unauthenticated", method: request.method });
      return errorResponse(401, CODE_UNAUTHENTICATED, "Authentication error");
    }
    const client = deps.policy[identity.clientId];
    if (client === undefined) {
      // Authenticated by Access but not named in the policy: no access, and no hint why.
      deps.log({ event: "denied", reason: "client not in policy", client: identity.clientId, method: request.method });
      return errorResponse(403, CODE_DENIED, "this client is not permitted");
    }

    let outcome: { response: Response; hostname?: string; tunnel?: string };
    let op: string;
    if (target.kind === "collection" && request.method === "GET") {
      op = "list";
      outcome = await list(client, request);
    } else if (target.kind === "collection" && request.method === "POST") {
      op = "create";
      outcome = await create(client, request);
    } else if (target.kind === "item" && request.method === "PATCH") {
      op = "patch";
      outcome = await patch(client, target.id, request);
    } else if (target.kind === "item" && request.method === "DELETE") {
      op = "delete";
      outcome = await remove(client, target.id);
    } else {
      return errorResponse(405, 1000, "method not allowed");
    }

    deps.log({
      event: outcome.response.ok ? "allowed" : "refused",
      client: identity.clientId,
      op,
      status: outcome.response.status,
      hostname: outcome.hostname,
      tunnel: outcome.tunnel,
      id: target.kind === "item" ? target.id : undefined,
    });
    return outcome.response;
  };
}
