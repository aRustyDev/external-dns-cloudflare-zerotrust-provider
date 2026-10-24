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

// Verifies the Cloudflare Access JWT that Access attaches to a request it has let through. Access
// itself checks the service token; this check is the Worker not trusting that the request really
// came through Access, so a request that reached the Worker some other way is refused.

export interface AccessConfig {
  /** The Access team domain, for example "myteam.cloudflareaccess.com". */
  teamDomain: string;
  /** The audience tag of the Access application in front of this Worker. */
  aud: string;
}

/** Who made the request. Only service tokens are accepted, so this is a service-token client id. */
export interface Identity {
  clientId: string;
}

export interface Jwks {
  keys: Array<JsonWebKey & { kid?: string }>;
}

/** Returns the team's signing keys. forceRefresh asks for a fresh copy, for an unknown key id. */
export type JwksProvider = (forceRefresh: boolean) => Promise<Jwks>;

const decoder = new TextDecoder();
const encoder = new TextEncoder();

function base64UrlToBytes(value: string): Uint8Array {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (value.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function parseSegment(segment: string): Record<string, unknown> | null {
  try {
    const value: unknown = JSON.parse(decoder.decode(base64UrlToBytes(segment)));
    return typeof value === "object" && value !== null && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

/**
 * Verifies an Access JWT and returns the service-token identity, or null for anything else: a bad
 * signature, the wrong issuer or audience, an expired token, an algorithm other than RS256, or a
 * token for a person rather than a service token. A null result always means "refuse".
 */
export async function verifyAccessJwt(
  token: string,
  config: AccessConfig,
  getJwks: JwksProvider,
  nowSeconds: number,
): Promise<Identity | null> {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const header = parseSegment(parts[0]);
  const claims = parseSegment(parts[1]);
  if (header === null || claims === null) return null;

  // Never accept the algorithm the token asks for: only RS256, which is what Access signs with.
  if (header.alg !== "RS256" || typeof header.kid !== "string") return null;

  let jwk = (await getJwks(false)).keys.find((k) => k.kid === header.kid);
  if (jwk === undefined) jwk = (await getJwks(true)).keys.find((k) => k.kid === header.kid);
  if (jwk === undefined) return null;

  let valid = false;
  try {
    const key = await crypto.subtle.importKey(
      "jwk",
      jwk,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["verify"],
    );
    valid = await crypto.subtle.verify(
      "RSASSA-PKCS1-v1_5",
      key,
      // A fresh array owns its whole buffer, so passing the buffer itself is exact.
      base64UrlToBytes(parts[2]).buffer as ArrayBuffer,
      encoder.encode(`${parts[0]}.${parts[1]}`),
    );
  } catch {
    return null;
  }
  if (!valid) return null;

  if (claims.iss !== `https://${config.teamDomain}`) return null;
  const aud = claims.aud;
  if (!(aud === config.aud || (Array.isArray(aud) && aud.includes(config.aud)))) return null;
  if (typeof claims.exp !== "number" || claims.exp <= nowSeconds) return null;
  if (typeof claims.nbf === "number" && claims.nbf > nowSeconds) return null;

  // A service token's JWT carries its client id as common_name. A person's JWT carries an email and
  // no common_name, and must not be able to act as a client.
  if (typeof claims.common_name !== "string" || claims.common_name === "") return null;
  return { clientId: claims.common_name };
}

/**
 * A JwksProvider that fetches the team's keys and caches them. A forced refresh is honoured at
 * most once a minute, so a stream of tokens with unknown key ids cannot turn the Worker into a
 * request amplifier against Access.
 */
export function cachedJwks(
  teamDomain: string,
  fetchImpl: typeof fetch,
  now: () => number = () => Date.now(),
): JwksProvider {
  const ttlMs = 10 * 60 * 1000;
  const minRefreshMs = 60 * 1000;
  let cached: Jwks | undefined;
  let fetchedAt = 0;

  return async (forceRefresh: boolean): Promise<Jwks> => {
    const age = now() - fetchedAt;
    const stale = cached === undefined || age > ttlMs;
    const refresh = stale || (forceRefresh && age > minRefreshMs);
    if (!refresh && cached !== undefined) return cached;

    const res = await fetchImpl(`https://${teamDomain}/cdn-cgi/access/certs`);
    if (!res.ok) {
      if (cached !== undefined) return cached; // keep serving the last good keys
      throw new Error(`could not fetch Access signing keys: HTTP ${res.status}`);
    }
    const body = (await res.json()) as Jwks;
    if (!Array.isArray(body.keys)) throw new Error("Access signing keys response has no keys");
    cached = body;
    fetchedAt = now();
    return cached;
  };
}
