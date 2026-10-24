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

import { cachedJwks, verifyAccessJwt, type AccessConfig, type Jwks } from "../src/access.ts";

const config: AccessConfig = { teamDomain: "team.cloudflareaccess.com", aud: "the-aud-tag" };
const NOW = 1_800_000_000;

function b64url(input: Uint8Array | string): string {
  const bytes = typeof input === "string" ? new TextEncoder().encode(input) : input;
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function newKey(kid: string) {
  const pair = (await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const jwk = { ...(await crypto.subtle.exportKey("jwk", pair.publicKey)), kid, alg: "RS256", use: "sig" };
  return { privateKey: pair.privateKey, jwk };
}

async function sign(
  privateKey: CryptoKey,
  header: Record<string, unknown>,
  claims: Record<string, unknown>,
): Promise<string> {
  const signingInput = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(claims))}`;
  const sig = new Uint8Array(
    await crypto.subtle.sign("RSASSA-PKCS1-v1_5", privateKey, new TextEncoder().encode(signingInput)),
  );
  return `${signingInput}.${b64url(sig)}`;
}

const goodClaims = {
  iss: `https://${config.teamDomain}`,
  aud: [config.aud],
  exp: NOW + 600,
  common_name: "client-x.access",
};

describe("verifyAccessJwt", () => {
  it("accepts a valid service-token JWT and returns its client id", async () => {
    const key = await newKey("k1");
    const token = await sign(key.privateKey, { alg: "RS256", kid: "k1" }, goodClaims);
    const id = await verifyAccessJwt(token, config, async () => ({ keys: [key.jwk] }), NOW);
    assert.deepEqual(id, { clientId: "client-x.access" });
  });

  it("accepts an audience given as a plain string", async () => {
    const key = await newKey("k1");
    const token = await sign(key.privateKey, { alg: "RS256", kid: "k1" }, { ...goodClaims, aud: config.aud });
    assert.ok(await verifyAccessJwt(token, config, async () => ({ keys: [key.jwk] }), NOW));
  });

  // Every refusal below returns null, which the broker turns into a 401.
  it("refuses a token signed by a different key that claims the same kid", async () => {
    const real = await newKey("k1");
    const attacker = await newKey("k1");
    const token = await sign(attacker.privateKey, { alg: "RS256", kid: "k1" }, goodClaims);
    assert.equal(await verifyAccessJwt(token, config, async () => ({ keys: [real.jwk] }), NOW), null);
  });

  it("refuses a token whose payload was changed after signing", async () => {
    const key = await newKey("k1");
    const token = await sign(key.privateKey, { alg: "RS256", kid: "k1" }, goodClaims);
    const [h, , s] = token.split(".");
    const forged = `${h}.${b64url(JSON.stringify({ ...goodClaims, common_name: "someone-else.access" }))}.${s}`;
    assert.equal(await verifyAccessJwt(forged, config, async () => ({ keys: [key.jwk] }), NOW), null);
  });

  it("refuses any algorithm but RS256, including none", async () => {
    const key = await newKey("k1");
    const jwks = async (): Promise<Jwks> => ({ keys: [key.jwk] });
    for (const alg of ["none", "HS256", "RS512", "ES256"]) {
      const unsigned = `${b64url(JSON.stringify({ alg, kid: "k1" }))}.${b64url(JSON.stringify(goodClaims))}.`;
      assert.equal(await verifyAccessJwt(unsigned, config, jwks, NOW), null, alg);
    }
  });

  for (const [name, claims] of [
    ["the wrong issuer", { ...goodClaims, iss: "https://evil.cloudflareaccess.com" }],
    ["the wrong audience", { ...goodClaims, aud: ["another-app"] }],
    ["no audience", { ...goodClaims, aud: undefined }],
    ["an expired token", { ...goodClaims, exp: NOW - 1 }],
    ["a token with no expiry", { ...goodClaims, exp: undefined }],
    ["a token that is not valid yet", { ...goodClaims, nbf: NOW + 100 }],
    ["a person's token, which has no common_name", { ...goodClaims, common_name: undefined, email: "a@b.c" }],
    ["an empty common_name", { ...goodClaims, common_name: "" }],
    ["a common_name that is not a string", { ...goodClaims, common_name: 7 }],
  ] as Array<[string, Record<string, unknown>]>) {
    it(`refuses ${name}`, async () => {
      const key = await newKey("k1");
      const token = await sign(key.privateKey, { alg: "RS256", kid: "k1" }, claims);
      assert.equal(await verifyAccessJwt(token, config, async () => ({ keys: [key.jwk] }), NOW), null);
    });
  }

  it("refuses malformed tokens", async () => {
    const jwks = async (): Promise<Jwks> => ({ keys: [] });
    for (const bad of ["", "a.b", "a.b.c.d", "!!!.!!!.!!!", `${b64url("not json")}.${b64url("{}")}.x`]) {
      assert.equal(await verifyAccessJwt(bad, config, jwks, NOW), null, JSON.stringify(bad));
    }
  });

  it("refuses a token with no kid", async () => {
    const key = await newKey("k1");
    const token = await sign(key.privateKey, { alg: "RS256" }, goodClaims);
    assert.equal(await verifyAccessJwt(token, config, async () => ({ keys: [key.jwk] }), NOW), null);
  });

  it("refetches the keys once for an unknown kid, which is how a key rotation is picked up", async () => {
    const oldKey = await newKey("old");
    const newer = await newKey("new");
    const token = await sign(newer.privateKey, { alg: "RS256", kid: "new" }, goodClaims);
    const forced: boolean[] = [];
    const id = await verifyAccessJwt(
      token,
      config,
      async (force) => {
        forced.push(force);
        return { keys: force ? [oldKey.jwk, newer.jwk] : [oldKey.jwk] };
      },
      NOW,
    );
    assert.deepEqual(id, { clientId: "client-x.access" });
    assert.deepEqual(forced, [false, true]);
  });

  it("refuses an unknown kid that is still unknown after the refetch", async () => {
    const key = await newKey("k1");
    const token = await sign(key.privateKey, { alg: "RS256", kid: "ghost" }, goodClaims);
    assert.equal(await verifyAccessJwt(token, config, async () => ({ keys: [key.jwk] }), NOW), null);
  });
});

describe("cachedJwks", () => {
  function fakeFetch(bodies: Array<Jwks | number>) {
    const calls: string[] = [];
    const impl = (async (url: string) => {
      calls.push(url);
      const next = bodies[Math.min(calls.length - 1, bodies.length - 1)];
      if (typeof next === "number") return new Response("", { status: next });
      return new Response(JSON.stringify(next), { status: 200 });
    }) as unknown as typeof fetch;
    return { impl, calls };
  }

  it("fetches the team's key URL once and then serves from cache", async () => {
    const { impl, calls } = fakeFetch([{ keys: [] }]);
    const provider = cachedJwks("team.cloudflareaccess.com", impl, () => 1_000);
    await provider(false);
    await provider(false);
    assert.deepEqual(calls, ["https://team.cloudflareaccess.com/cdn-cgi/access/certs"]);
  });

  it("refreshes after the time-to-live", async () => {
    const { impl, calls } = fakeFetch([{ keys: [] }]);
    let now = 0;
    const provider = cachedJwks("t", impl, () => now);
    await provider(false);
    now = 11 * 60 * 1000;
    await provider(false);
    assert.equal(calls.length, 2);
  });

  it("honours a forced refresh at most once a minute", async () => {
    const { impl, calls } = fakeFetch([{ keys: [] }]);
    let now = 0;
    const provider = cachedJwks("t", impl, () => now);
    await provider(false);
    now = 10_000;
    await provider(true); // too soon after the first fetch
    assert.equal(calls.length, 1);
    now = 61_000;
    await provider(true);
    assert.equal(calls.length, 2);
  });

  it("keeps serving the last good keys when a refresh fails", async () => {
    const good: Jwks = { keys: [{ kid: "k" }] };
    const { impl } = fakeFetch([good, 500]);
    let now = 0;
    const provider = cachedJwks("t", impl, () => now);
    await provider(false);
    now = 11 * 60 * 1000;
    assert.deepEqual(await provider(false), good);
  });

  it("throws when it has never had keys and the fetch fails", async () => {
    const { impl } = fakeFetch([503]);
    await assert.rejects(() => cachedJwks("t", impl)(false), /HTTP 503/);
  });
});
