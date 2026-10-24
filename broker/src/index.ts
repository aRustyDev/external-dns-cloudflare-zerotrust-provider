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

// The Worker entry point: wires configuration from the environment into the handler. All the
// decisions live in handler.ts and policy.ts, which are tested without a Worker runtime.

import { cachedJwks, verifyAccessJwt, type JwksProvider } from "./access.ts";
import { createHandler } from "./handler.ts";
import { parsePolicy, type Policy } from "./policy.ts";

export interface Env {
  /** Secret. The account-wide Cloudflare token with Cloudflare One Networks write. */
  CF_API_TOKEN: string;
  /** Secret or var. The Cloudflare account id. */
  CF_ACCOUNT_ID: string;
  /** Var. The policy as JSON; see policy.ts. */
  POLICY: string;
  /** Var. The Access team domain, for example "myteam.cloudflareaccess.com". */
  ACCESS_TEAM_DOMAIN: string;
  /** Var. The audience tag of the Access application in front of this Worker. */
  ACCESS_AUD: string;
  /** Var, optional. Overrides Cloudflare's API root; used only for testing. */
  UPSTREAM_BASE?: string;
}

const DEFAULT_UPSTREAM = "https://api.cloudflare.com/client/v4";

// Parsed once per isolate and again only if the policy variable changes.
let parsed: { source: string; policy: Policy } | undefined;
let jwks: { teamDomain: string; provider: JwksProvider } | undefined;

function policyFor(env: Env): Policy {
  if (parsed === undefined || parsed.source !== env.POLICY) {
    parsed = { source: env.POLICY, policy: parsePolicy(env.POLICY) };
  }
  return parsed.policy;
}

function jwksFor(env: Env): JwksProvider {
  if (jwks === undefined || jwks.teamDomain !== env.ACCESS_TEAM_DOMAIN) {
    jwks = { teamDomain: env.ACCESS_TEAM_DOMAIN, provider: cachedJwks(env.ACCESS_TEAM_DOMAIN, fetch) };
  }
  return jwks.provider;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    let handle: (request: Request) => Promise<Response>;
    try {
      for (const name of ["CF_API_TOKEN", "CF_ACCOUNT_ID", "POLICY", "ACCESS_TEAM_DOMAIN", "ACCESS_AUD"] as const) {
        if (!env[name]) throw new Error(`${name} is not set`);
      }
      const policy = policyFor(env);
      const provider = jwksFor(env);
      handle = createHandler({
        policy,
        accountId: env.CF_ACCOUNT_ID,
        upstreamBase: env.UPSTREAM_BASE ?? DEFAULT_UPSTREAM,
        upstreamToken: env.CF_API_TOKEN,
        authenticate: async (req) => {
          const jwt = req.headers.get("Cf-Access-Jwt-Assertion");
          if (jwt === null) return null;
          return verifyAccessJwt(
            jwt,
            { teamDomain: env.ACCESS_TEAM_DOMAIN, aud: env.ACCESS_AUD },
            provider,
            Math.floor(Date.now() / 1000),
          );
        },
        fetch,
        log: (line) => console.log(JSON.stringify(line)),
      });
    } catch (e) {
      // Fail closed. A broker that cannot read its configuration answers nothing.
      console.error(JSON.stringify({ event: "misconfigured", error: (e as Error).message }));
      return new Response(
        JSON.stringify({ success: false, errors: [{ code: 1000, message: "broker is misconfigured" }], messages: [], result: null }),
        { status: 500, headers: { "content-type": "application/json" } },
      );
    }
    return handle(request);
  },
};
