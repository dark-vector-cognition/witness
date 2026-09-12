#!/usr/bin/env node
// witness — the DVC agent flight recorder (v0.1 recorder slice)
//   witness [--as <principal>] [--name <server>] [--allow key,key] -- <command> [args...]
//   witness verify [file|dir]
//   witness tail [--all]
//   witness sessions
import { readFileSync } from "node:fs";
import path from "node:path";
import { runProxy } from "../lib/proxy.mjs";
import { verifyChain } from "../lib/record.mjs";
import { listSessionFiles, logDir, readRecords } from "../lib/session-log.mjs";

const argv = process.argv.slice(2);

function usage(code = 0) {
  process.stderr.write(`witness — record what your agents actually did, at the tool boundary.

  witness [--as <principal>] [--name <server>] [--allow k1,k2] -- <command> [args...]
      Run <command> as an MCP stdio server behind a transparent recorder.
  witness verify [file|dir]     Walk hash chains; report the first broken link. Exit 1 on failure.
  witness tail [--all]          Follow the newest session (or all) as human-readable lines.
  witness sessions              List recorded sessions.

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

if (argv[0] === "verify") {
  const target = argv[1] ? path.resolve(argv[1]) : logDir();
  let files;
  try { files = target.endsWith(".jsonl") ? [target] : listSessionFiles(target); } catch { files = []; }
  if (files.length === 0) { process.stdout.write(`no sessions found under ${target}\n`); process.exit(0); }
  let failed = 0;
  for (const file of files) {
    const result = verifyChain(readRecords(file));
    process.stdout.write(`${result.ok ? "OK  " : "FAIL"} ${path.basename(file)}  ${result.count} records${result.ok ? "" : ` — ${result.reason}`}\n`);
    if (!result.ok) failed += 1;
  }
  process.stdout.write(`${files.length - failed}/${files.length} chains verified\n`);
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
} else {
  // proxy mode
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
