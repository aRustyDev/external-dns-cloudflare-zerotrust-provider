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

import {
  commentAllowed,
  hostnameAllowed,
  normalizeHostname,
  parsePolicy,
  tunnelAllowed,
  type ClientPolicy,
} from "../src/policy.ts";

const client: ClientPolicy = {
  owner: "cluster-a",
  tunnels: ["aaaa1111-0000-0000-0000-000000000000"],
  suffixes: ["edns.woven"],
};

describe("parsePolicy", () => {
  it("parses a valid policy and normalizes it", () => {
    const p = parsePolicy(
      JSON.stringify({
        "x.access": { owner: "cluster-a", tunnels: ["AAAA-1", "aaaa-1"], suffixes: [".Edns.Woven.", "*.apps.woven"] },
      }),
    );
    assert.deepEqual(p["x.access"], {
      owner: "cluster-a",
      tunnels: ["aaaa-1"],
      suffixes: ["edns.woven", "apps.woven"],
    });
  });

  it("treats owner as optional", () => {
    const p = parsePolicy(JSON.stringify({ c: { tunnels: ["t"], suffixes: ["s.woven"] } }));
    assert.equal(p.c.owner, undefined);
  });

  // A policy that is misread grants access instead of denying it, so every ambiguity is an error.
  for (const [name, doc, message] of [
    ["invalid JSON", "{nope", /not valid JSON/],
    ["not an object", "[]", /JSON object/],
    ["no clients", "{}", /no clients/],
    ["client is not an object", '{"c": 3}', /must be an object/],
    ["empty client id", '{" ": {"tunnels":["t"],"suffixes":["s"]}}', /empty client id/],
    ["missing tunnels", '{"c": {"suffixes":["s"]}}', /tunnels must be a non-empty list/],
    ["empty tunnels", '{"c": {"tunnels":[],"suffixes":["s"]}}', /tunnels must be a non-empty list/],
    ["missing suffixes", '{"c": {"tunnels":["t"]}}', /suffixes must be a non-empty list/],
    ["blank tunnel", '{"c": {"tunnels":[" "],"suffixes":["s"]}}', /non-empty strings/],
    ["non-string suffix", '{"c": {"tunnels":["t"],"suffixes":[1]}}', /non-empty strings/],
    ["a suffix that normalizes to nothing", '{"c": {"tunnels":["t"],"suffixes":["*."]}}', /empty or wildcard suffix/],
    ["a typo in a key", '{"c": {"tunnel":["t"],"tunnels":["t"],"suffixes":["s"]}}', /unknown key "tunnel"/],
    ["owner with a slash", '{"c": {"owner":"a/b","tunnels":["t"],"suffixes":["s"]}}', /owner must be/],
    ["owner with a space", '{"c": {"owner":"a b","tunnels":["t"],"suffixes":["s"]}}', /owner must be/],
    ["owner that is not a string", '{"c": {"owner":5,"tunnels":["t"],"suffixes":["s"]}}', /owner must be/],
  ] as Array<[string, string, RegExp]>) {
    it(`refuses ${name}`, () => assert.throws(() => parsePolicy(doc), message));
  }

  it("refuses a tunnel assigned to two clients", () => {
    assert.throws(
      () =>
        parsePolicy(
          JSON.stringify({
            a: { tunnels: ["T1"], suffixes: ["s"] },
            b: { tunnels: ["t1"], suffixes: ["s"] },
          }),
        ),
      /tunnel t1 is assigned to both/,
    );
  });

  it("allows overlapping suffixes, which a handoff between two clients needs", () => {
    const p = parsePolicy(
      JSON.stringify({
        a: { tunnels: ["t1"], suffixes: ["edns.woven"] },
        b: { tunnels: ["t2"], suffixes: ["edns.woven"] },
      }),
    );
    assert.equal(Object.keys(p).length, 2);
  });
});

describe("normalizeHostname", () => {
  it("lowercases, drops trailing dots and a leading wildcard", () => {
    assert.equal(normalizeHostname("  Foo.Edns.Woven.. "), "foo.edns.woven");
    assert.equal(normalizeHostname("*.apps.woven"), "apps.woven");
  });
});

describe("hostnameAllowed", () => {
  it("allows the suffix itself and its subdomains", () => {
    assert.ok(hostnameAllowed(client, "edns.woven"));
    assert.ok(hostnameAllowed(client, "foo.edns.woven"));
    assert.ok(hostnameAllowed(client, "a.b.edns.woven"));
  });

  it("matches on whole labels, so a longer name that merely ends the same is refused", () => {
    assert.ok(!hostnameAllowed(client, "evilEdns.woven"));
    assert.ok(!hostnameAllowed(client, "xedns.woven"));
    assert.ok(!hostnameAllowed(client, "edns.woven.evil.com"));
    assert.ok(!hostnameAllowed(client, "woven"));
  });

  it("ignores case, a trailing dot, and checks a wildcard by its stored form", () => {
    assert.ok(hostnameAllowed(client, "FOO.EDNS.WOVEN."));
    assert.ok(hostnameAllowed(client, "*.edns.woven"));
    assert.ok(!hostnameAllowed(client, "*.other.woven"));
  });

  it("refuses anything that is not a non-empty string", () => {
    for (const bad of [undefined, null, 3, {}, [], "", " ", "."]) {
      assert.ok(!hostnameAllowed(client, bad), `accepted ${JSON.stringify(bad)}`);
    }
  });
});

describe("tunnelAllowed", () => {
  it("allows only the client's own tunnels, ignoring case and spaces", () => {
    assert.ok(tunnelAllowed(client, "aaaa1111-0000-0000-0000-000000000000"));
    assert.ok(tunnelAllowed(client, " AAAA1111-0000-0000-0000-000000000000 "));
    assert.ok(!tunnelAllowed(client, "bbbb2222-0000-0000-0000-000000000000"));
  });

  it("refuses anything that is not a string", () => {
    for (const bad of [undefined, null, 1, {}, ["aaaa1111-0000-0000-0000-000000000000"]]) {
      assert.ok(!tunnelAllowed(client, bad), `accepted ${JSON.stringify(bad)}`);
    }
  });
});

describe("commentAllowed", () => {
  const tag = "managed-by=external-dns/cluster-a";

  it("requires an owned client to write exactly its own tag", () => {
    assert.ok(commentAllowed(client, tag, true));
    assert.ok(commentAllowed(client, `  ${tag}  `, true));
    assert.ok(!commentAllowed(client, "managed-by=external-dns/cluster-b", true));
    assert.ok(!commentAllowed(client, `${tag}-evil`, true));
    assert.ok(!commentAllowed(client, "hand-written", true));
    assert.ok(!commentAllowed(client, "", true));
  });

  it("refuses a missing comment when one is required, and allows it when it is not", () => {
    assert.ok(!commentAllowed(client, undefined, true));
    assert.ok(!commentAllowed(client, null, true));
    assert.ok(commentAllowed(client, undefined, false));
  });

  it("refuses a comment that is not a string", () => {
    assert.ok(!commentAllowed(client, 5, false));
    assert.ok(!commentAllowed(client, { a: 1 }, false));
  });

  it("lets a client with no owner write any comment, and omit it", () => {
    const open: ClientPolicy = { tunnels: ["t"], suffixes: ["s"] };
    assert.ok(commentAllowed(open, "anything", true));
    assert.ok(commentAllowed(open, undefined, true));
  });
});
