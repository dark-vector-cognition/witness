import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { verifyChain } from "../lib/record.mjs";
import { isWrapped, rewriteConfig, unwrapEntry, wrapEntry } from "../lib/wrap.mjs";

const bin = new URL("../bin/witness.mjs", import.meta.url).pathname;
const fake = new URL("./fixtures/fake-mcp-server.mjs", import.meta.url).pathname;

function run(args, env = {}) {
  return new Promise((resolve) => {
    const p = spawn(process.execPath, [bin, ...args], { env: { ...process.env, ...env } });
    let out = ""; let err = "";
    p.stdout.on("data", (c) => { out += c; }); p.stderr.on("data", (c) => { err += c; });
    p.on("exit", (code) => resolve({ code, out, err }));
  });
}

async function recordSession(home, { name = "fake", as = "tester@dvc", calls = ["echo", "fail"] } = {}) {
  const p = spawn(process.execPath, [bin, "--as", as, "--name", name, "--", process.execPath, fake], { env: { ...process.env, WITNESS_HOME: home }, stdio: ["pipe", "ignore", "ignore"] });
  p.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { clientInfo: { name: "t", version: "1" } } })}\n`);
  calls.forEach((tool, i) => p.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id: 10 + i, method: "tools/call", params: { name: tool, arguments: { i } } })}\n`));
  await new Promise((r) => setTimeout(r, 300));
  p.stdin.end();
  await new Promise((r) => p.on("exit", r));
}

test("wrap/unwrap round-trip a config, preserve env, keep a backup, and are idempotent", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "witness-cfg-"));
  const file = path.join(dir, ".mcp.json");
  const original = { mcpServers: { github: { command: "npx", args: ["-y", "@modelcontextprotocol/server-github"], env: { GITHUB_TOKEN: "x" } }, remote: { url: "https://example.com/mcp" } } };
  await writeFile(file, `${JSON.stringify(original, null, 2)}\n`);
  const dry = rewriteConfig(file, { mode: "wrap", principal: "hank@dvc", dryRun: true });
  assert.deepEqual(dry.changes, ["github"]);
  assert.deepEqual(JSON.parse(await readFile(file, "utf8")), original, "dry run writes nothing");
  const wrapped = rewriteConfig(file, { mode: "wrap", principal: "hank@dvc" });
  assert.deepEqual(wrapped.changes, ["github"]);
  assert.equal(wrapped.skipped[0].name, "remote");
  const after = JSON.parse(await readFile(file, "utf8"));
  assert.equal(after.mcpServers.github.command, process.execPath);
  assert.ok(after.mcpServers.github.args[0].endsWith("bin/witness.mjs"));
  assert.deepEqual(after.mcpServers.github.args.slice(1), ["--name", "github", "--as", "hank@dvc", "--", "npx", "-y", "@modelcontextprotocol/server-github"]);
  assert.deepEqual(after.mcpServers.github.env, { GITHUB_TOKEN: "x" }, "env block preserved");
  assert.deepEqual(after.mcpServers.remote, original.mcpServers.remote, "url-based servers untouched");
  assert.deepEqual(JSON.parse(await readFile(`${file}.witness-bak`, "utf8")), original);
  assert.deepEqual(rewriteConfig(file, { mode: "wrap", principal: "hank@dvc" }).changes, [], "second wrap is a no-op");
  assert.ok(isWrapped(after.mcpServers.github));
  const restored = rewriteConfig(file, { mode: "unwrap" });
  assert.deepEqual(restored.changes, ["github"]);
  assert.deepEqual(JSON.parse(await readFile(file, "utf8")), original, "unwrap restores the original exactly");
  assert.deepEqual(unwrapEntry(wrapEntry("x", { command: "c" }).entry).entry, { command: "c" });
  await rm(dir, { recursive: true, force: true });
});

test("query filters joined call rows; report summarises tools, errors, latency, integrity", async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), "witness-w2-"));
  await recordSession(home, { name: "alpha", calls: ["echo", "echo", "fail"] });
  await recordSession(home, { name: "beta", as: "other@dvc", calls: ["echo", "hang"] });
  const all = await run(["query", "--json"], { WITNESS_HOME: home });
  const rows = all.out.trim().split("\n").map((l) => JSON.parse(l));
  assert.equal(rows.length, 5);
  const errors = await run(["query", "--status", "error", "--json"], { WITNESS_HOME: home });
  assert.equal(errors.out.trim().split("\n").length, 1);
  const beta = await run(["query", "--server", "beta", "--json"], { WITNESS_HOME: home });
  assert.deepEqual(beta.out.trim().split("\n").map((l) => JSON.parse(l).status), ["ok", "unknown"]);
  const byAs = await run(["query", "--as", "other@dvc", "--json"], { WITNESS_HOME: home });
  assert.equal(byAs.out.trim().split("\n").length, 2);
  const report = await run(["report", "--since", "1h"], { WITNESS_HOME: home });
  assert.equal(report.code, 0);
  assert.match(report.out, /\| 2 \| 2 \| 2 \| 5 \| 1 \(20%\) \| 1 \| 0 \|/, "sessions/servers/principals/calls/errors/unanswered/broken");
  assert.match(report.out, /\| echo \| 3 \| 0 \| 0 \| \d+ \| \d+ \|/);
  assert.match(report.out, /\| hang \| 1 \| 0 \| 1 \|/);
  assert.match(report.out, /2 chain\(s\) verified, no broken links/);
  assert.match(report.out, /declared, not verified/);
  const old = await run(["report", "--since", "2026-01-01T00:00:00Z"], { WITNESS_HOME: home });
  assert.match(old.out, /\| 5 \|/, "absolute --since is accepted");
  await rm(home, { recursive: true, force: true });
});

test("anchor appends chain heads once per change, in a chain of its own", async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), "witness-anchor-"));
  await recordSession(home, { name: "alpha" });
  const first = await run(["anchor"], { WITNESS_HOME: home });
  assert.match(first.out, /1 checkpoint\(s\) appended \(1 total\)/);
  const again = await run(["anchor"], { WITNESS_HOME: home });
  assert.match(again.out, /0 checkpoint\(s\) appended \(1 total\)/, "unchanged heads are not re-anchored");
  await recordSession(home, { name: "beta" });
  const third = await run(["anchor"], { WITNESS_HOME: home });
  assert.match(third.out, /1 checkpoint\(s\) appended \(2 total\)/);
  const checkpoints = (await readFile(path.join(home, "checkpoints.jsonl"), "utf8")).trim().split("\n").map((l) => JSON.parse(l));
  assert.equal(verifyChain(checkpoints).ok, true);
  assert.ok(checkpoints.every((c) => c.verified === true && /^[0-9a-f]{64}$/.test(c.head)));
  await rm(home, { recursive: true, force: true });
});
