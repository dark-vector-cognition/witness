import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, readdir, readFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { verifyChain } from "../lib/record.mjs";

const bin = new URL("../bin/witness.mjs", import.meta.url).pathname;
const fake = new URL("./fixtures/fake-mcp-server.mjs", import.meta.url).pathname;

const frames = [
  { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", clientInfo: { name: "test-harness", version: "9.9.9" }, capabilities: {} } },
  { jsonrpc: "2.0", method: "notifications/initialized" },
  { jsonrpc: "2.0", id: 2, method: "tools/list" },
  { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "echo", arguments: { repo: "dvc/witness", api_key: "SHOULD-NEVER-APPEAR", note: "x".repeat(300) } } },
  { jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "fail", arguments: {} } },
  { jsonrpc: "2.0", id: 5, method: "tools/call", params: { name: "soft-fail", arguments: {} } },
  { jsonrpc: "2.0", id: 6, method: "tools/call", params: { name: "hang", arguments: { why: "never answered" } } },
];

async function runSession({ env = {}, extraArgs = [] } = {}) {
  const home = await mkdtemp(path.join(os.tmpdir(), "witness-"));
  const proc = spawn(process.execPath, [bin, "--as", "tester@dvc", "--name", "fake", "--allow", "repo,api_key", ...extraArgs, "--", process.execPath, fake], { env: { ...process.env, WITNESS_HOME: home, ...env }, stdio: ["pipe", "pipe", "pipe"] });
  let stdout = ""; let stderr = "";
  proc.stdout.on("data", (chunk) => { stdout += chunk; });
  proc.stderr.on("data", (chunk) => { stderr += chunk; });
  for (const frame of frames) proc.stdin.write(`${JSON.stringify(frame)}\n`);
  proc.stdin.write("# not json at all\n");
  await new Promise((resolve) => setTimeout(resolve, 400));
  proc.stdin.end();
  const code = await new Promise((resolve) => proc.on("exit", resolve));
  const dir = path.join(home, "log");
  const files = await readdir(dir).catch(() => []);
  const records = files.length ? (await readFile(path.join(dir, files[0]), "utf8")).trim().split("\n").filter(Boolean).map((l) => JSON.parse(l)) : [];
  return { home, code, stdout, stderr, records, cleanup: () => rm(home, { recursive: true, force: true }) };
}

test("relay is transparent: every server frame reaches the client byte-for-byte", async () => {
  const s = await runSession();
  const lines = s.stdout.split("\n").filter(Boolean);
  const replies = lines.filter((l) => l.startsWith("{")).map((l) => JSON.parse(l));
  assert.deepEqual(replies.map((r) => r.id), [1, 2, 3, 4, 5]);
  assert.equal(replies[0].result.serverInfo.name, "fake-server");
  assert.ok(lines.includes("# server-side noise line"), "non-JSON server output must pass through");
  assert.equal(s.code, 0);
  await s.cleanup();
});

test("records session, client identity, tool calls and outcomes; args are hashed with allow-listed summary only", async () => {
  const s = await runSession();
  const by = (event) => s.records.filter((r) => r.event === event);
  assert.equal(by("session_start").length, 1);
  assert.equal(by("session_start")[0].principal.as, "tester@dvc");
  assert.equal(by("session_start")[0].principal.verified, false);
  assert.equal(by("session_client")[0].actor.client, "test-harness");
  const calls = by("tool_call");
  assert.deepEqual(calls.map((c) => c.tool), ["echo", "fail", "soft-fail", "hang"]);
  const echo = calls[0];
  assert.match(echo.args_sha256, /^[0-9a-f]{64}$/);
  assert.deepEqual(Object.keys(echo.args_summary), ["repo"], "only allow-listed, non-secret keys are summarised");
  assert.equal(echo.args_summary.repo, "dvc/witness");
  const text = JSON.stringify(s.records);
  assert.doesNotMatch(text, /SHOULD-NEVER-APPEAR/, "secret values never reach the log");
  assert.doesNotMatch(text, /x{50}/, "raw argument bodies are not stored");
  const results = by("tool_result");
  const outcome = Object.fromEntries(results.map((r) => [r.tool, r.outcome.status]));
  assert.deepEqual(outcome, { echo: "ok", fail: "error", "soft-fail": "error", hang: "unknown" });
  assert.equal(results.find((r) => r.tool === "fail").outcome.code, -32000);
  assert.ok(results.every((r) => typeof r.outcome.ms === "number"));
  assert.equal(by("raw").length, 2, "one raw client line, one raw server line");
  const end = by("session_end")[0];
  assert.deepEqual(end.counts, { calls: 4, ok: 1, error: 2, raw: 2 });
  assert.equal(end.unresolved, 1);
  await s.cleanup();
});

test("chain verifies, and any edit breaks it at the edited record", async () => {
  const s = await runSession();
  assert.equal(verifyChain(s.records).ok, true);
  assert.ok(s.records.length >= 10);
  const tampered = structuredClone(s.records);
  tampered[3].tool = "something-else";
  const result = verifyChain(tampered);
  assert.equal(result.ok, false);
  assert.equal(result.brokenAt, 3);
  await s.cleanup();
});

test("witness verify exits 0 on a clean log and 1 on a tampered one", async () => {
  const s = await runSession();
  const run = (args) => new Promise((resolve) => { const p = spawn(process.execPath, [bin, ...args], { env: { ...process.env, WITNESS_HOME: s.home } }); let out = ""; p.stdout.on("data", (c) => { out += c; }); p.on("exit", (code) => resolve({ code, out })); });
  const clean = await run(["verify"]);
  assert.equal(clean.code, 0);
  assert.match(clean.out, /1\/1 chains verified/);
  const file = path.join(s.home, "log", (await readdir(path.join(s.home, "log")))[0]);
  const lines = (await readFile(file, "utf8")).trim().split("\n");
  const edited = JSON.parse(lines[2]); edited.tool = "edited"; lines[2] = JSON.stringify(edited);
  await (await import("node:fs/promises")).writeFile(file, `${lines.join("\n")}\n`);
  const bad = await run(["verify"]);
  assert.equal(bad.code, 1);
  assert.match(bad.out, /FAIL/);
  await s.cleanup();
});

test("a recorder that cannot write never breaks the relay", async () => {
  // A regular file used as the home directory: mkdir fails immediately with ENOTDIR on every platform.
  const blocker = path.join(await mkdtemp(path.join(os.tmpdir(), "witness-blocker-")), "not-a-dir");
  await (await import("node:fs/promises")).writeFile(blocker, "");
  const s = await runSession({ env: { WITNESS_HOME: blocker } });
  const replies = s.stdout.split("\n").filter((l) => l.startsWith("{")).map((l) => JSON.parse(l));
  assert.deepEqual(replies.map((r) => r.id), [1, 2, 3, 4, 5]);
  assert.match(s.stderr, /recording disabled/);
  assert.equal(s.code, 0);
});

test("server that exits mid-stream: relay stays up, open calls close as unknown, exit code propagates", async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), "witness-epipe-"));
  // A server that answers initialize then exits with code 3 while the client keeps writing.
  const dying = path.join(home, "dying.mjs");
  await (await import("node:fs/promises")).writeFile(dying, `import readline from "node:readline"; const rl = readline.createInterface({ input: process.stdin }); rl.on("line", (l) => { const m = JSON.parse(l); if (m.method === "initialize") { process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: m.id, result: { serverInfo: { name: "dying" } } }) + "\\n"); setTimeout(() => process.exit(3), 50); } });`);
  const proc = spawn(process.execPath, [bin, "--name", "dying", "--", process.execPath, dying], { env: { ...process.env, WITNESS_HOME: home }, stdio: ["pipe", "pipe", "pipe"] });
  let stderr = ""; proc.stderr.on("data", (c) => { stderr += c; });
  proc.stdin.on("error", () => {}); // the test keeps writing after the proxy has (correctly) exited
  const exited = new Promise((resolve) => proc.on("exit", resolve));
  proc.stdin.write(`${JSON.stringify(frames[0])}\n`);
  proc.stdin.write(`${JSON.stringify(frames[3])}\n`);
  await new Promise((r) => setTimeout(r, 300));
  for (let i = 0; i < 50; i += 1) { try { proc.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id: 100 + i, method: "tools/call", params: { name: "echo", arguments: {} } })}\n`); } catch { /* proxy gone */ } }
  await new Promise((r) => setTimeout(r, 200));
  try { proc.stdin.end(); } catch { /* proxy gone */ }
  const code = await exited;
  assert.equal(code, 3, "server exit code propagates");
  assert.doesNotMatch(stderr, /EPIPE|Unhandled|ERR_STREAM/, "no crash trace");
  const file = path.join(home, "log", (await readdir(path.join(home, "log")))[0]);
  const records = (await readFile(file, "utf8")).trim().split("\n").map((l) => JSON.parse(l));
  assert.equal(verifyChain(records).ok, true);
  assert.equal(records.at(-1).event, "session_end");
  assert.deepEqual(records.at(-1).exit, { code: 3, signal: null });
  await rm(home, { recursive: true, force: true });
});
