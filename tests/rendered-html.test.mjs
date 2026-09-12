import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

async function render() {
  const workerUrl = new URL("../dist/server/index.js", import.meta.url);
  workerUrl.searchParams.set("test", `${process.pid}-${Date.now()}`);
  const { default: worker } = await import(workerUrl.href);
  return worker.fetch(new Request("http://localhost/", { headers: { accept: "text/html" } }), { ASSETS: { fetch: async () => new Response("Not found", { status: 404 }) } }, { waitUntil() {}, passThroughOnException() {} });
}

test("renders the operator evidence surface", async () => {
  const response = await render();
  assert.equal(response.status, 200);
  const html = await response.text();
  assert.match(html, /Witness/);
  assert.match(html, /Agent Flight Recorder/);
  assert.match(html, /Mission timeline/);
  assert.match(html, /Permission &amp; approval matrix/);
  assert.match(html, /Source coverage manifest/);
  assert.match(html, /Replay, suspend, resume, terminate/);
  assert.match(html, /TicketBoard/);
  assert.match(html, /Stormbreaker/);
  assert.doesNotMatch(html, /codex-preview|Your site is taking shape/);
});

test("snapshot excludes secret-bearing keys", async () => {
  const raw = await readFile(new URL("../public/data/latest.json", import.meta.url), "utf8");
  assert.doesNotMatch(raw, /\"(?:token|secret|password|authorization|cookie|api[_-]?key)\"\s*:/i);
  const data = JSON.parse(raw);
  assert.ok(data.sources.length >= 2);
  assert.ok(data.chain.eventCount >= 4);
  assert.equal(data.controlContracts.find((item) => item.id === "replay").mode, "Simulation only");
  assert.equal(data.controlContracts.filter((item) => item.id !== "replay").every((item) => item.mode === "Live test adapter"), true);
  assert.ok(data.coverage.length >= 4);
  assert.equal(data.coverage.every((item) => ["observed", "confirmed_absent", "unreachable", "unsupported", "not_configured"].includes(item.status)), true);
});
