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

// The authorization policy: which tunnels and hostnames each client may touch. Everything here is
// pure, so the rules that decide what leaks and what does not can be tested without a network.

/** What one client, identified by its Access service-token client id, may do. */
export interface ClientPolicy {
  /**
   * When set, every comment this client writes must be exactly the provider's tag for this owner,
   * so a client cannot create a route that claims to belong to someone else.
   */
  owner?: string;
  /** Tunnel ids this client may list, create on, retarget to, and patch or delete routes from. */
  tunnels: string[];
  /** Hostname suffixes this client may manage. A suffix matches itself and any subdomain. */
  suffixes: string[];
}

/** Policy for every client, keyed by the Access service-token client id (the JWT common_name). */
export type Policy = Record<string, ClientPolicy>;

/** The tag the provider writes into a route comment: managed-by=external-dns/<owner>. */
export const OWNER_TAG_PREFIX = "managed-by=external-dns/";

/**
 * Lowercases a hostname, drops trailing dots, and drops a leading wildcard label. Cloudflare stores
 * a wildcard route without its "*." (measured 2026-10-23), so the stored form is what policy must
 * be checked against.
 */
export function normalizeHostname(hostname: string): string {
  let h = hostname.trim().toLowerCase();
  while (h.endsWith(".")) h = h.slice(0, -1);
  if (h.startsWith("*.")) h = h.slice(2);
  while (h.startsWith(".")) h = h.slice(1);
  return h;
}

const CLIENT_KEYS = new Set(["owner", "tunnels", "suffixes"]);

function stringList(value: unknown, what: string): string[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error(`${what} must be a non-empty list`);
  }
  return value.map((item) => {
    if (typeof item !== "string" || item.trim() === "") {
      throw new Error(`${what} must contain only non-empty strings`);
    }
    return item.trim();
  });
}

/**
 * Parses and validates the policy. It throws on anything ambiguous, because a policy that is
 * silently misread would grant access rather than deny it: unknown keys (a typo such as "tunnel"),
 * empty lists, and a tunnel claimed by two clients.
 */
export function parsePolicy(raw: string): Policy {
  let doc: unknown;
  try {
    doc = JSON.parse(raw);
  } catch (e) {
    throw new Error(`policy is not valid JSON: ${(e as Error).message}`);
  }
  if (typeof doc !== "object" || doc === null || Array.isArray(doc)) {
    throw new Error("policy must be a JSON object keyed by client id");
  }

  const policy: Policy = {};
  const tunnelOwner = new Map<string, string>();
  for (const [clientId, value] of Object.entries(doc as Record<string, unknown>)) {
    const where = `client "${clientId}"`;
    if (clientId.trim() === "") throw new Error("policy has an empty client id");
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
      throw new Error(`${where} must be an object`);
    }
    const entry = value as Record<string, unknown>;
    for (const key of Object.keys(entry)) {
      if (!CLIENT_KEYS.has(key)) throw new Error(`${where} has an unknown key "${key}"`);
    }

    const tunnels = stringList(entry.tunnels, `${where} tunnels`).map((t) => t.toLowerCase());
    const suffixes = stringList(entry.suffixes, `${where} suffixes`).map(normalizeHostname);
    if (suffixes.some((s) => s === "" || s.includes("*"))) {
      throw new Error(`${where} has an empty or wildcard suffix`);
    }

    let owner: string | undefined;
    if (entry.owner !== undefined) {
      if (typeof entry.owner !== "string" || !/^[^\s/]+$/.test(entry.owner)) {
        throw new Error(`${where} owner must be a non-empty string without spaces or "/"`);
      }
      owner = entry.owner;
    }

    for (const tunnel of tunnels) {
      const holder = tunnelOwner.get(tunnel);
      if (holder !== undefined && holder !== clientId) {
        throw new Error(`tunnel ${tunnel} is assigned to both "${holder}" and "${clientId}"`);
      }
      tunnelOwner.set(tunnel, clientId);
    }
    policy[clientId] = { owner, tunnels: [...new Set(tunnels)], suffixes: [...new Set(suffixes)] };
  }
  if (Object.keys(policy).length === 0) throw new Error("policy has no clients");
  return policy;
}

/** Whether the client may act on this tunnel. Anything that is not a string is refused. */
export function tunnelAllowed(client: ClientPolicy, tunnelId: unknown): boolean {
  return typeof tunnelId === "string" && client.tunnels.includes(tunnelId.trim().toLowerCase());
}

/**
 * Whether the client may manage this hostname: it equals one of its suffixes or is a subdomain of
 * one. The match is on whole labels, so the suffix "private" does not admit "evilprivate".
 */
export function hostnameAllowed(client: ClientPolicy, hostname: unknown): boolean {
  if (typeof hostname !== "string") return false;
  const h = normalizeHostname(hostname);
  // Only a single leading wildcard label is meaningful, and normalizeHostname has removed it. A
  // wildcard anywhere else is not a form Cloudflare stores, so it is refused rather than matched.
  if (h === "" || h.includes("*")) return false;
  return client.suffixes.some((s) => h === s || h.endsWith(`.${s}`));
}

/**
 * Whether a comment is acceptable. A client without an owner may write any comment. A client with
 * one may write only its own tag. A missing comment is refused when it is required (a create), so
 * an owned client cannot create an untagged route, and allowed when it is not (a patch that leaves
 * the comment alone).
 */
export function commentAllowed(client: ClientPolicy, comment: unknown, required: boolean): boolean {
  if (comment === undefined || comment === null) return !(required && client.owner !== undefined);
  if (typeof comment !== "string") return false;
  if (client.owner === undefined) return true;
  return comment.trim() === `${OWNER_TAG_PREFIX}${client.owner}`;
}
