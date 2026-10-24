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

// A local server for the Go end-to-end test (test/broker). It runs the real broker handler in front
// of an in-memory fake Cloudflare, so the real Go client and provider can be driven against the
// real policy code without a network or a Worker runtime.
//
// TEST ONLY. It trusts the Cf-Access-Client-Id header as the caller's identity, which is exactly
// what a deployed broker must never do: there, identity comes from a verified Access JWT. It also
// serves /__state and /__calls so the test can inspect the fake upstream.

import http from "node:http";
import type { AddressInfo } from "node:net";

import { createHandler } from "../src/handler.ts";
import { ACCOUNT, POLICY, SECRET, fakeCloudflare, initialRoutes } from "../test/support.ts";

const upstream = fakeCloudflare(initialRoutes());

const handle = createHandler({
  policy: POLICY,
  accountId: ACCOUNT,
  upstreamBase: "https://upstream.test/client/v4",
  upstreamToken: SECRET,
  authenticate: async (request) => {
    const id = request.headers.get("cf-access-client-id");
    return id === null ? null : { clientId: id };
  },
  fetch: upstream.impl,
  log: () => {},
});

const server = http.createServer(async (req, res) => {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  const body = Buffer.concat(chunks);

  if (req.url === "/__state") {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify(upstream.routes));
    return;
  }
  if (req.url === "/__calls") {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify(upstream.calls));
    return;
  }

  const headers = new Headers();
  for (const [name, value] of Object.entries(req.headers)) {
    if (typeof value === "string") headers.set(name, value);
  }
  const method = req.method ?? "GET";
  const request = new Request(`http://${req.headers.host}${req.url}`, {
    method,
    headers,
    body: method === "GET" || method === "HEAD" ? undefined : body,
  });
  const response = await handle(request);
  res.writeHead(response.status, { "content-type": "application/json" });
  res.end(await response.text());
});

server.listen(0, "127.0.0.1", () => {
  // The Go test reads this line to learn the port.
  console.log(`LISTENING ${(server.address() as AddressInfo).port}`);
});
