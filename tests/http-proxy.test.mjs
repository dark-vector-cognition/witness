import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { startHttpProxy } from "../lib/http-proxy.mjs";
import { verifyChain } from "../lib/record.mjs";
import { readRecords } from "../lib/session-log.mjs";

// Fake remote MCP server: JSON for initialize, SSE for tools/call, legacy GET stream, echoes auth header presence.
function fakeUpstream() {
  const seen = [];
  const server = createServer(async (req, res) => {
    const chunks = []; for await (const c of req) chunks.push(c);
    const body = Buffer.concat(chunks).toString("utf8");
    seen.push({ method: req.method, url: req.url, auth: req.headers.authorization || null, body });
    if (req.method === "GET") {
      res.writeHead(200, { "content-type": "text/event-stream" });
      res.write(`event: message\ndata: ${JSON.stringify({ jsonrpc: "2.0", method: "notifications/ping" })}\n\n`);
      res.end(); return;
    }
    const msg = JSON.parse(body);
    if (msg.method === "initialize") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { serverInfo: { name: "fake-http" } } })); return;
    }
    if (msg.method === "tools/call") {
      res.writeHead(200, { "content-type": "text/event-stream" });
      const isErr = msg.params.name === "fail";
      const payload = isErr
        ? { jsonrpc: "2.0", id: msg.id, error: { code: -32001, message: "nope" } }
        : { jsonrpc: "2.0", id: msg.id, result: { content: [{ type: "text", text: `echo:${JSON.stringify(msg.params.arguments)}` }] } };
      const text = JSON.stringify(payload);
      // split the data line across two chunks to exercise the incremental parser
      res.write(`event: message\ndata: ${text.slice(0, 10)}`);
      setTimeout(() => { res.write(`${text.slice(10)}\n\n`); res.end(); }, 20);
      return;
    }
    res.writeHead(202); res.end();
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve({ server, seen, url: `http://127.0.0.1:${server.address().port}/mcp` })));
}

test("http proxy relays JSON + SSE byte-for-byte, records calls/results, chain verifies, auth never logged", async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), "witness-http-"));
  const up = await fakeUpstream();
  const proxy = await startHttpProxy({ upstream: up.url, principal: "tester@example.com", serverName: "fake-http", allowKeys: ["i"], logDir: path.join(home, "log"), stderr: { write() {} } });
  const post = (msg) => fetch(proxy.local, { method: "POST", headers: { "content-type": "application/json", authorization: "Bearer SECRET-TOKEN" }, body: JSON.stringify(msg) });

  const init = await post({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", clientInfo: { name: "t", version: "1" } } });
  assert.equal(init.status, 200);
  assert.deepEqual(await init.json(), { jsonrpc: "2.0", id: 1, result: { serverInfo: { name: "fake-http" } } });

  const ok = await post({ jsonrpc: "2.0", id: 10, method: "tools/call", params: { name: "echo", arguments: { i: 1, token: "hide" } } });
  assert.equal(ok.headers.get("content-type"), "text/event-stream");
  const okText = await ok.text();
  assert.match(okText, /^event: message\ndata: \{"jsonrpc"/);
  assert.ok(okText.endsWith("\n\n"));

  const fail = await post({ jsonrpc: "2.0", id: 11, method: "tools/call", params: { name: "fail", arguments: {} } });
  assert.match(await fail.text(), /"code":-32001/);

  const legacy = await fetch(proxy.local, { method: "GET", headers: { accept: "text/event-stream" } });
  assert.match(await legacy.text(), /notifications\/ping/);

  await post({ jsonrpc: "2.0", method: "notifications/initialized" });

  assert.equal(up.seen[0].auth, "Bearer SECRET-TOKEN", "authorization passes through");
  assert.equal(up.seen[0].url, "/mcp", "upstream path preserved");

  await proxy.close();
  const records = readRecords(proxy.file);
  assert.equal(verifyChain(records).ok, true);
  const raw = JSON.stringify(records);
  assert.ok(!raw.includes("SECRET-TOKEN"), "auth header never recorded");
  assert.ok(!raw.includes("hide"), "denied arg key never recorded");
  const events = records.map((r) => r.event);
  assert.deepEqual(events, ["session_start", "session_client", "tool_call", "tool_result", "tool_call", "tool_result", "notification", "session_end"]);
  const calls = records.filter((r) => r.event === "tool_call");
  assert.equal(calls[0].tool, "echo"); assert.deepEqual(calls[0].args_summary, { i: 1 });
  assert.equal(calls[0].principal.as, "tester@example.com"); assert.equal(calls[0].server.transport, "http");
  const results = records.filter((r) => r.event === "tool_result");
  assert.equal(results[0].outcome.status, "ok"); assert.equal(results[0].call_seq, calls[0].seq);
  assert.equal(results[1].outcome.status, "error"); assert.equal(results[1].outcome.code, -32001);
  const end = records.at(-1);
  assert.deepEqual({ calls: end.counts.calls, ok: end.counts.ok, error: end.counts.error, unresolved: end.unresolved }, { calls: 2, ok: 1, error: 1, unresolved: 0 });
  assert.equal(records[1].actor.client, "t");

  up.server.close(); up.server.closeAllConnections?.();
  await rm(home, { recursive: true, force: true });
});

test("http proxy answers 502 JSON-RPC when upstream is down and seals the session", async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), "witness-http-"));
  const up = await fakeUpstream(); const dead = up.url; up.server.close();
  const proxy = await startHttpProxy({ upstream: dead, logDir: path.join(home, "log"), stderr: { write() {} } });
  const res = await fetch(proxy.local, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 5, method: "tools/call", params: { name: "x", arguments: {} } }) });
  assert.equal(res.status, 502);
  assert.equal((await res.json()).error.code, -32000);
  await proxy.close();
  const records = readRecords(proxy.file);
  assert.equal(verifyChain(records).ok, true);
  assert.ok(records.some((r) => r.event === "error" && /unreachable/.test(r.message)));
  const unknown = records.find((r) => r.event === "tool_result");
  assert.equal(unknown.outcome.status, "unknown");
  assert.equal(records.at(-1).unresolved, 1);
  await rm(home, { recursive: true, force: true });
});
