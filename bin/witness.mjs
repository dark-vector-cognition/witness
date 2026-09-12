#!/usr/bin/env node
// witness — the DVC agent flight recorder (v0.1 recorder slice)
//   witness [--as <principal>] [--name <server>] [--allow key,key] -- <command> [args...]
//   witness verify [file|dir]
//   witness tail [--all]
//   witness sessions
import { readFileSync } from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { anchor, buildReport, queryCalls } from "../lib/analyze.mjs";
import { startHttpProxy } from "../lib/http-proxy.mjs";
import { runProxy } from "../lib/proxy.mjs";
import { candidateConfigs, rewriteConfig } from "../lib/wrap.mjs";
import { verifyChain } from "../lib/record.mjs";
import { listSessionFiles, logDir, readRecords } from "../lib/session-log.mjs";

const argv = process.argv.slice(2);

function usage(code = 0) {
  process.stderr.write(`witness — record what your agents actually did, at the tool boundary.

  witness [--as <principal>] [--name <server>] [--allow k1,k2] -- <command> [args...]
      Run <command> as an MCP stdio server behind a transparent recorder.
  witness http --upstream <url> [--listen 127.0.0.1:0] [--as p] [--name s] [--allow k,k]
      Local reverse proxy for a remote MCP server (Streamable HTTP or SSE). Prints the address to point your harness at.
  witness wrap [config] [--as p] [--dry-run] [--node /path/node] [--bin /path/witness.mjs]
                                Rewrite MCP config entries to run through Witness (keeps a .witness-bak).
  witness unwrap [config]                      Reverse it.
  witness verify [file|dir]     Walk hash chains; report the first broken link. Exit 1 on failure.
  witness tail [--all]          Follow the newest session (or all) as human-readable lines.
  witness sessions              List recorded sessions.
  witness query [--tool t] [--server s] [--as p] [--status ok|error|unknown|open] [--since 24h] [--json]
  witness report [--since 7d]   Markdown digest: calls by tool/server/principal, error rate, latency, integrity.
  witness anchor [--git]        Append every chain head to checkpoints.jsonl (chained); --git commits it in WITNESS_HOME.

Records: ${logDir()}  (override with WITNESS_HOME). Args and results are hashed, not stored.
`);
  process.exit(code);
}

function fmt(record) {
  const t = record.ts?.slice(11, 19) || "";
  switch (record.event) {
    case "session_start": return `${t}  ▶ session ${record.session} · server ${record.server?.name} · as ${record.principal?.as ?? "—"}`;
    case "session_client": return `${t}  · client ${record.actor?.client} ${record.actor?.version ?? ""}`.trimEnd();
    case "tool_call": return `${t}  → ${record.tool}  args:${record.args_sha256?.slice(0, 10)}${record.args_summary ? " " + JSON.stringify(record.args_summary) : ""}`;
    case "tool_result": return `${t}  ${record.outcome?.status === "ok" ? "✓" : record.outcome?.status === "error" ? "✗" : "?"} ${record.tool}  ${record.outcome?.ms ?? "?"}ms${record.outcome?.reason ? " · " + record.outcome.reason : ""}`;
    case "session_end": return `${t}  ■ session end · ${record.counts?.calls ?? 0} calls (${record.counts?.ok ?? 0} ok, ${record.counts?.error ?? 0} error) · exit ${record.exit?.code ?? record.exit?.signal}`;
    case "raw": return `${t}  ~ raw ${record.direction} ${record.bytes}B`;
    case "error": return `${t}  ! ${record.message}`;
    default: return `${t}  · ${record.event}`;
  }
}

if (argv.length === 0 || argv[0] === "-h" || argv[0] === "--help") usage(0);

function opt(name, fallback = null) { const i = argv.indexOf(name); return i !== -1 && argv[i + 1] !== undefined ? argv[i + 1] : fallback; }

if (argv[0] === "http") {
  const upstream = opt("--upstream");
  if (!upstream) { process.stderr.write("witness http: --upstream <url> is required\n"); process.exit(2); }
  const [listenHost, listenPort] = String(opt("--listen", "127.0.0.1:0")).split(":");
  const allowKeys = String(opt("--allow", "")).split(",").map((s) => s.trim()).filter(Boolean);
  const proxy = await startHttpProxy({ upstream, listenHost: listenHost || "127.0.0.1", listenPort: Number(listenPort || 0), principal: opt("--as", process.env.WITNESS_AS || null), serverName: opt("--name"), allowKeys });
  process.stdout.write(`${JSON.stringify({ listen: proxy.local, upstream, session: proxy.session, log: proxy.file })}\n`);
  process.stderr.write(`[witness] recording ${upstream} at ${proxy.local} — point your MCP config's "url" here. Ctrl-C to stop.\n`);
  const stop = async () => { await proxy.close(); process.exit(0); };
  process.on("SIGINT", stop); process.on("SIGTERM", stop);
} else if (argv[0] === "wrap" || argv[0] === "unwrap") {
  const mode = argv[0];
  const optValues = new Set([opt("--as"), opt("--node"), opt("--bin")].filter(Boolean));
  const explicit = argv.slice(1).find((a) => !a.startsWith("--") && !optValues.has(a));
  const principal = opt("--as", process.env.WITNESS_AS || null);
  const dryRun = argv.includes("--dry-run");
  const targets = explicit ? [{ harness: "config", file: path.resolve(explicit), key: "mcpServers" }] : candidateConfigs();
  if (targets.length === 0) { process.stdout.write("no MCP config found (looked for .mcp.json, ~/.claude.json, ~/.cursor/mcp.json, Claude Desktop). Pass a path.\n"); process.exit(1); }
  let touched = 0;
  for (const target of targets) {
    let result;
    try { result = rewriteConfig(target.file, { mode, principal, key: target.key, dryRun, node: opt("--node") || undefined, bin: opt("--bin") || undefined }); } catch (error) { process.stdout.write(`SKIP ${target.harness}: ${error.message}\n`); continue; }
    if (result.note) { process.stdout.write(`SKIP ${target.harness}: ${result.note}\n`); continue; }
    const verb = mode === "wrap" ? "wrapped" : "unwrapped";
    process.stdout.write(`${dryRun ? "DRY " : ""}${target.harness} ${target.file}\n  ${result.changes.length ? `${verb}: ${result.changes.join(", ")}` : `nothing to ${mode}`}${result.skipped.length ? `\n  skipped: ${result.skipped.map((s) => `${s.name} (${s.reason})`).join(", ")}` : ""}\n`);
    touched += result.changes.length;
  }
  if (mode === "wrap" && touched && !dryRun) process.stdout.write(`\nRestart the harness. Then: witness tail\n`);
  process.exit(0);
}

if (argv[0] === "query") {
  const rows = queryCalls({ tool: opt("--tool"), server: opt("--server"), as: opt("--as"), status: opt("--status"), since: opt("--since") });
  if (argv.includes("--json")) { for (const r of rows) process.stdout.write(`${JSON.stringify(r)}\n`); process.exit(0); }
  process.stdout.write(`${rows.length} call(s)\n`);
  for (const r of rows) process.stdout.write(`${r.ts}  ${r.server.padEnd(14)} ${r.tool.padEnd(28)} ${(r.status === "ok" ? "✓" : r.status === "error" ? "✗" : "?")} ${String(r.ms ?? "—").padStart(6)}ms  as ${r.principal ?? "—"}${r.summary ? "  " + JSON.stringify(r.summary) : ""}\n`);
  process.exit(0);
}

if (argv[0] === "report") {
  process.stdout.write(`${buildReport({ since: opt("--since", "7d") })}\n`);
  process.exit(0);
}

if (argv[0] === "anchor") {
  const result = anchor();
  if (!result.ok) { process.stdout.write(`FAIL ${result.reason}\n`); process.exit(1); }
  process.stdout.write(`${result.appended} checkpoint(s) appended (${result.total} total) → ${result.file}\n`);
  if (argv.includes("--git")) {
    const home = path.dirname(result.file);
    const git = (...a) => spawnSync("git", ["-C", home, ...a], { encoding: "utf8" });
    if (git("rev-parse", "--is-inside-work-tree").status !== 0) git("init", "-q");
    git("add", "checkpoints.jsonl");
    const commit = git("commit", "-q", "-m", `witness anchor ${new Date().toISOString()}`);
    process.stdout.write(commit.status === 0 ? `committed in ${home}\n` : `nothing new to commit\n`);
  }
  process.exit(0);
}

if (argv[0] === "verify") {
  const target = argv[1] ? path.resolve(argv[1]) : logDir();
  let files;
  try { files = target.endsWith(".jsonl") ? [target] : listSessionFiles(target); } catch { files = []; }
  if (files.length === 0) { process.stdout.write(`no sessions found under ${target}\n`); process.exit(0); }
  let failed = 0; let chains = 0;
  for (const file of files) {
    // A file may hold one session or a concatenated export of several; each session is its own chain.
    const bySession = new Map();
    for (const record of readRecords(file)) { const key = record.session ?? "?"; if (!bySession.has(key)) bySession.set(key, []); bySession.get(key).push(record); }
    for (const [session, records] of bySession) {
      const result = verifyChain(records); chains += 1;
      const label = bySession.size > 1 ? `${path.basename(file)} ${session}` : path.basename(file);
      process.stdout.write(`${result.ok ? "OK  " : "FAIL"} ${label}  ${result.count} records${result.ok ? "" : ` — ${result.reason}`}\n`);
      if (!result.ok) failed += 1;
    }
  }
  process.stdout.write(`${chains - failed}/${chains} chains verified\n`);
  process.exit(failed ? 1 : 0);
}

if (argv[0] === "sessions") {
  for (const file of listSessionFiles()) {
    const records = readRecords(file);
    const start = records.find((r) => r.event === "session_start");
    const end = records.find((r) => r.event === "session_end");
    process.stdout.write(`${path.basename(file, ".jsonl")}  ${start?.ts ?? ""}  ${start?.server?.name ?? "?"}  ${end ? `${end.counts?.calls ?? 0} calls` : "open"}\n`);
  }
  process.exit(0);
}

if (argv[0] === "tail") {
  const all = argv.includes("--all");
  const files = listSessionFiles();
  const targets = all ? files : files.slice(-1);
  if (targets.length === 0) { process.stdout.write(`no sessions yet under ${logDir()}\n`); process.exit(0); }
  const offsets = new Map();
  const drain = () => {
    for (const file of all ? listSessionFiles() : targets) {
      let text;
      try { text = readFileSync(file, "utf8"); } catch { continue; }
      const seen = offsets.get(file) ?? 0;
      const fresh = text.slice(seen);
      offsets.set(file, text.length);
      for (const line of fresh.split("\n").filter(Boolean)) {
        try { process.stdout.write(`${fmt(JSON.parse(line))}\n`); } catch { /* partial line; next tick */ offsets.set(file, text.length - line.length); }
      }
    }
  };
  drain();
  setInterval(drain, 500);
} else if (argv[0] !== "http") {
  // proxy mode (http mode is long-running and dispatched above)
  let principal = process.env.WITNESS_AS || null;
  let serverName = null;
  let allowKeys = [];
  let i = 0;
  for (; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--") { i += 1; break; }
    if (arg === "--as") principal = argv[++i];
    else if (arg === "--name") serverName = argv[++i];
    else if (arg === "--allow") allowKeys = String(argv[++i] || "").split(",").map((s) => s.trim()).filter(Boolean);
    else { process.stderr.write(`unknown option ${arg}\n`); usage(2); }
  }
  const [command, ...args] = argv.slice(i);
  if (!command) usage(2);
  runProxy({ command, args, principal, serverName, allowKeys });
}
