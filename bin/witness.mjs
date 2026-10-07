#!/usr/bin/env node
// witness — transparent MCP proxy + tamper-evident record (format v0.1)
//   witness [--as <principal>] [--name <server>] [--allow key,key] -- <command> [args...]
//   witness verify [file|dir]
//   witness tail [--all]
//   witness sessions
import { readFileSync } from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { anchor, buildReport, queryCalls } from "../lib/analyze.mjs";
import { startHttpProxy } from "../lib/http-proxy.mjs";
import { EXIT_CODES, defaultModel, judgeDir, keySigner, runJudge, publicKeyLoader } from "../lib/judge.mjs";
import { DEFAULT_HOST, DEFAULT_PORT, feedChainRule, matchFeed, publishFeed, pullFeed, readFeedFile, startFeedServer, verifyFeedChain } from "../lib/feed.mjs";
import { keygen } from "../lib/keys.mjs";
import { runProxy } from "../lib/proxy.mjs";
import { runScore } from "../lib/score.mjs";
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
  witness wrap [config] [--as p] [--dry-run] [--via npx|path] [--node /path/node] [--bin /path/witness.mjs]
                                Rewrite MCP config entries to run through Witness (keeps a .witness-bak).
                                --via npx writes "npx -y @darkvectorcognition.ai/witness@<ver>"; --via path writes "node <bin>". Default matches this install.
  witness unwrap [config]                      Reverse it.
  witness verify [file|dir]     Walk hash chains; report the first broken link. Exit 1 on failure.
  witness tail [--all]          Follow the newest session (or all) as human-readable lines.
  witness sessions              List recorded sessions.
  witness query [--tool t] [--server s] [--as p] [--status ok|error|unknown|open] [--since 24h] [--json]
  witness report [--since 7d]   Markdown digest: calls by tool/server/principal, error rate, latency, integrity.
  witness anchor [--git]        Append every chain head to checkpoints.jsonl (chained); --git commits it in WITNESS_HOME.
  witness judge <session|file> [--vendor anthropic|openrouter|ollama|stub] [--model m] [--key k] [--json]  Fresh-model review (metadata view) to judge/<session>.jsonl. Exit 0 clean, 2 flagged, 3 tampered, 1 error.
  witness score [--since 30d] [--half-life 14d] [--json]  Label every call, Brier-score each judge, append to judge/. Prints judge_id, event_class, n, brier, rank, role.
  witness keygen                Make an ed25519 key pair in keys/. Prints the key_id. Never overwrites a key.
  witness feed publish --key <key_id>   Sign every new local refusal indicator into feed/published.jsonl. Exit 0 ok, 1 error, 3 broken chain.
  witness feed serve [--host 127.0.0.1] [--port 7480] [--any-interface]   Read-only HTTP: GET /feed and GET /feed?after=<seq>. Nothing else.
                                --host 0.0.0.0 or :: (every interface) needs --any-interface. An empty --host is refused.
  witness feed pull <url>       Verify a peer's /feed and append it to feed/remote/<key_id>.jsonl. Exit 0 ok, 1 error, 3 bad line.
  witness feed match <sha256>   Exit 0 when an indicator digest is in any feed file, 1 when not, 2 on an error.

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
  const optValues = new Set([opt("--as"), opt("--node"), opt("--bin"), opt("--via")].filter(Boolean));
  const explicit = argv.slice(1).find((a) => !a.startsWith("--") && !optValues.has(a));
  const principal = opt("--as", process.env.WITNESS_AS || null);
  const dryRun = argv.includes("--dry-run");
  const targets = explicit ? [{ harness: "config", file: path.resolve(explicit), key: "mcpServers" }] : candidateConfigs();
  if (targets.length === 0) { process.stdout.write("no MCP config found (looked for .mcp.json, ~/.claude.json, ~/.cursor/mcp.json, Claude Desktop). Pass a path.\n"); process.exit(1); }
  let touched = 0;
  for (const target of targets) {
    let result;
    try { result = rewriteConfig(target.file, { mode, principal, key: target.key, dryRun, node: opt("--node") || undefined, bin: opt("--bin") || undefined, via: opt("--via") || undefined }); } catch (error) { process.stdout.write(`SKIP ${target.harness}: ${error.message}\n`); continue; }
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

if (argv[0] === "judge") {
  const optValues = new Set([opt("--model"), opt("--vendor"), opt("--key")].filter(Boolean));
  const subject = argv.slice(1).find((a) => !a.startsWith("--") && !optValues.has(a));
  if (!subject) { process.stderr.write("witness judge: <session|file> is required\n"); process.exit(1); }
  try {
    const vendor = opt("--vendor", "anthropic");
    const model = opt("--model") || defaultModel(vendor);
    const key = opt("--key");
    const record = await runJudge({ subject, judge: { vendor, model }, signer: key ? keySigner(key) : null });
    if (argv.includes("--json")) process.stdout.write(`${JSON.stringify(record)}\n`);
    else process.stdout.write(`${record.verdict.toUpperCase()} ${record.subject.session}  ${record.findings.length} finding(s)  judge ${record.judge.id} (${record.judge.view})  seq ${record.seq} in ${path.join(judgeDir(), `${record.subject.session}.jsonl`)}\n${record.findings.map((f) => `  ${f.severity} seq ${f.call_seq ?? "?"}: ${f.note}\n`).join("")}`);
    process.exit(EXIT_CODES[record.verdict] ?? 1);
  } catch (error) {
    process.stderr.write(`witness judge: ${error.message}\n`);
    process.exit(1);
  }
}

if (argv[0] === "keygen") {
  try {
    const { keyId, keyFile, pubFile } = keygen();
    process.stdout.write(`${keyId}\n`);
    process.stderr.write(`[witness] wrote ${keyFile} and ${pubFile}. Give peers the .pub file. The .key file never leaves this machine.\n`);
    process.exit(0);
  } catch (error) {
    process.stderr.write(`witness keygen: ${error.message}\n`);
    process.exit(1);
  }
}

if (argv[0] === "feed") {
  const sub = argv[1];
  const fail = (error) => {
    process.stderr.write(`witness feed ${sub}: ${error.message}\n`);
    process.exit(error.exitCode ?? 1);
  };
  if (sub === "publish") {
    try {
      const result = publishFeed({ keyId: opt("--key") });
      process.stdout.write(`${result.appended} record(s) appended to ${result.file}\n`);
      if (result.skipped) process.stderr.write(`witness feed publish: skipped ${result.skipped} local record(s) that are not feed records with an indicator\n`);
      process.exit(0);
    } catch (error) { fail(error); }
  } else if (sub === "serve") {
    const host = opt("--host", DEFAULT_HOST);
    const port = Number(opt("--port", String(DEFAULT_PORT)));
    if (!Number.isInteger(port) || port < 0 || port > 65535) fail(new Error("--port must be an integer from 0 to 65535"));
    try {
      const feed = await startFeedServer({ host, port, anyInterface: argv.includes("--any-interface"), onWarn: (message) => process.stderr.write(`[witness] ${message}\n`) });
      process.stdout.write(`${JSON.stringify({ listen: feed.url, file: feed.file })}\n`);
      process.stderr.write(`[witness] serving ${feed.file} read-only at ${feed.url}. Ctrl-C to stop.\n`);
      if (!/^(127\.|::1$)/.test(feed.host)) process.stderr.write(`[witness] ${feed.host} is not a loopback address. Every host that can reach it can read the feed.\n`);
      const stop = async () => { await feed.close(); process.exit(0); };
      process.on("SIGINT", stop); process.on("SIGTERM", stop);
    } catch (error) { fail(error); }
  } else if (sub === "pull") {
    try {
      const result = await pullFeed({ url: argv.slice(2).find((a) => !a.startsWith("--")) });
      process.stdout.write(`${result.appended} record(s) appended${result.file ? ` to ${result.file}` : ""}\n`);
      process.exit(0);
    } catch (error) {
      if (error.appended !== undefined) process.stdout.write(`${error.appended} record(s) appended${error.file ? ` to ${error.file}` : ""}\n`);
      fail(error);
    }
  } else if (sub === "match") {
    const result = matchFeed(argv[2]);
    for (const hit of result.hits) process.stdout.write(`${hit.file}  ${hit.kind}\n`);
    for (const message of result.errors) process.stderr.write(`witness feed match: ${message}\n`);
    if (result.code === 1) process.stderr.write("witness feed match: not found\n");
    process.exit(result.code);
  } else {
    process.stderr.write("witness feed: publish, serve, pull or match. See witness --help.\n");
    process.exit(1);
  }
}

if (argv[0] === "score") {
  try {
    const rows = runScore({ since: opt("--since", "30d"), halfLife: opt("--half-life", "14d"), onWarn: (m) => process.stderr.write(`witness score: ${m}\n`) });
    if (argv.includes("--json")) { for (const r of rows) process.stdout.write(`${JSON.stringify(r)}\n`); process.exit(0); }
    if (rows.length === 0) { process.stdout.write("no scored votes\n"); process.exit(0); }
    process.stdout.write(`${"judge_id".padEnd(28)} ${"event_class".padEnd(24)} ${"n".padStart(5)} ${"brier".padStart(7)} ${"rank".padStart(4)}  role\n`);
    for (const r of rows) process.stdout.write(`${r.judge_id.padEnd(28)} ${r.event_class.padEnd(24)} ${String(r.n).padStart(5)} ${r.brier.toFixed(4).padStart(7)} ${String(r.rank ?? "-").padStart(4)}  ${r.role}\n`);
    process.exit(0);
  } catch (error) {
    process.stderr.write(`witness score: ${error.message}\n`);
    process.exit(1);
  }
}

if (argv[0] === "verify") {
  const target = argv[1] ? path.resolve(argv[1]) : logDir();
  let files;
  try { files = target.endsWith(".jsonl") ? [target] : listSessionFiles(target); } catch { files = []; }
  // The feed directory: its remote copies are chains too.
  if (!target.endsWith(".jsonl") && path.basename(target) === "feed") files.push(...listSessionFiles(path.join(target, "remote")));
  if (files.length === 0) { process.stdout.write(`no sessions found under ${target}\n`); process.exit(0); }
  let failed = 0; let chains = 0;
  for (const file of files) {
    // A feed file by its path is read with the strict feed parser. Any other file is read as before, then checked for published records.
    let rule = feedChainRule(file);
    const all = rule ? null : readRecords(file);
    if (!rule) rule = feedChainRule(file, all);
    if (rule) {
      // A feed file is one chain. Published and remote copies need a trusted signer on every record (SPEC-0.2 section 5).
      // A blank or unparseable line is a FAIL, not a crash.
      const parsed = readFeedFile(file);
      const result = parsed.problem ? { ok: false, count: 0, reason: parsed.problem } : verifyFeedChain(parsed.records, rule); chains += 1;
      process.stdout.write(`${result.ok ? "OK  " : "FAIL"} ${path.basename(file)}  ${result.count} records${rule.signed ? " (signed)" : ""}${result.ok ? "" : `: ${result.reason}`}\n`);
      if (!result.ok) failed += 1;
      continue;
    }
    // A file may hold one session or a concatenated export of several; each session is its own chain.
    const bySession = new Map();
    for (const record of all) { const key = record.session ?? "?"; if (!bySession.has(key)) bySession.set(key, []); bySession.get(key).push(record); }
    for (const [session, records] of bySession) {
      const result = verifyChain(records, { publicKeys: publicKeyLoader() }); chains += 1;
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
} else if (argv[0] !== "http" && argv[0] !== "feed") {
  // proxy mode (http mode and feed serve are long-running and dispatched above)
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
