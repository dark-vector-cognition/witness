// query / report / anchor over recorded sessions. The log is the truth; everything here is derived and disposable.
import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { GENESIS, sealRecord, verifyChain } from "./record.mjs";
import { listSessionFiles, logDir, readRecords, witnessHome } from "./session-log.mjs";

export function parseSince(text, now = Date.now()) {
  if (!text) return 0;
  const m = /^(\d+)([mhdw])$/.exec(text);
  if (!m) { const t = Date.parse(text); return Number.isNaN(t) ? 0 : t; }
  const unit = { m: 60e3, h: 3600e3, d: 86400e3, w: 7 * 86400e3 }[m[2]];
  return now - Number(m[1]) * unit;
}

/** Load all sessions; join tool_call ↔ tool_result into call rows. */
export function loadCalls({ dir = logDir(), since = 0 } = {}) {
  const sessions = [];
  const calls = [];
  for (const file of listSessionFiles(dir)) {
    let records;
    try { records = readRecords(file); } catch { sessions.push({ file, broken: true, reason: "unreadable" }); continue; }
    const chain = verifyChain(records);
    const start = records.find((r) => r.event === "session_start");
    const client = records.find((r) => r.event === "session_client");
    const end = records.find((r) => r.event === "session_end");
    const session = { file, id: start?.session ?? path.basename(file, ".jsonl"), server: start?.server?.name ?? "?", principal: start?.principal?.as ?? null, client: client?.actor?.client ?? start?.actor?.client ?? "unknown", startedAt: start?.ts ?? null, endedAt: end?.ts ?? null, broken: !chain.ok, reason: chain.reason, records: records.length };
    sessions.push(session);
    const results = new Map(records.filter((r) => r.event === "tool_result").map((r) => [r.call_seq, r]));
    for (const r of records) {
      if (r.event !== "tool_call") continue;
      if (since && Date.parse(r.ts) < since) continue;
      const res = results.get(r.seq);
      calls.push({ ts: r.ts, session: session.id, server: session.server, principal: session.principal, client: session.client, tool: r.tool, args_sha256: r.args_sha256, summary: r.args_summary ?? null, status: res?.outcome?.status ?? "open", ms: res?.outcome?.ms ?? null, code: res?.outcome?.code ?? null });
    }
  }
  return { sessions, calls };
}

export function queryCalls(filter = {}) {
  const { calls } = loadCalls({ since: parseSince(filter.since) });
  return calls.filter((c) => (!filter.tool || c.tool === filter.tool) && (!filter.server || c.server === filter.server) && (!filter.as || c.principal === filter.as) && (!filter.status || c.status === filter.status));
}

function pct(sorted, p) { if (!sorted.length) return null; return sorted[Math.min(sorted.length - 1, Math.floor(p * sorted.length))]; }

export function buildReport({ since = "7d" } = {}) {
  const cutoff = parseSince(since);
  const { sessions, calls } = loadCalls({ since: cutoff });
  const active = sessions.filter((s) => !s.startedAt || Date.parse(s.startedAt) >= cutoff || (s.endedAt && Date.parse(s.endedAt) >= cutoff));
  const byTool = new Map(); const byServer = new Map(); const byPrincipal = new Map(); const byHour = new Array(24).fill(0);
  for (const c of calls) {
    const t = byTool.get(c.tool) ?? { calls: 0, error: 0, open: 0, ms: [] }; t.calls += 1; if (c.status === "error") t.error += 1; if (c.status !== "ok" && c.status !== "error") t.open += 1; if (typeof c.ms === "number") t.ms.push(c.ms); byTool.set(c.tool, t);
    byServer.set(c.server, (byServer.get(c.server) ?? 0) + 1);
    byPrincipal.set(c.principal ?? "(none)", (byPrincipal.get(c.principal ?? "(none)") ?? 0) + 1);
    byHour[new Date(c.ts).getUTCHours()] += 1;
  }
  const errors = calls.filter((c) => c.status === "error").length;
  const unanswered = calls.filter((c) => c.status === "unknown" || c.status === "open").length;
  const broken = sessions.filter((s) => s.broken);
  const rows = [...byTool.entries()].sort((a, b) => b[1].calls - a[1].calls).map(([tool, t]) => { const s = t.ms.sort((x, y) => x - y); return `| ${tool} | ${t.calls} | ${t.error} | ${t.open} | ${pct(s, 0.5) ?? "—"} | ${pct(s, 0.95) ?? "—"} |`; });
  const peakHour = byHour.indexOf(Math.max(...byHour));
  const lines = [
    `# Witness report — last ${since}`,
    ``,
    `Generated ${new Date().toISOString()} · log ${logDir()}`,
    ``,
    `| Sessions | Servers | Principals | Tool calls | Errors | Unanswered | Broken chains |`,
    `|---|---|---|---|---|---|---|`,
    `| ${active.length} | ${byServer.size} | ${byPrincipal.size} | ${calls.length} | ${errors} (${calls.length ? Math.round((errors / calls.length) * 100) : 0}%) | ${unanswered} | ${broken.length} |`,
    ``,
    `## Calls by tool`,
    ``,
    `| Tool | Calls | Errors | Open | p50 ms | p95 ms |`,
    `|---|---|---|---|---|---|`,
    ...(rows.length ? rows : ["| — | 0 | 0 | 0 | — | — |"]),
    ``,
    `## Calls by server`,
    ``,
    ...[...byServer.entries()].sort((a, b) => b[1] - a[1]).map(([s, n]) => `- **${s}** — ${n}`),
    ``,
    `## Calls by declared principal`,
    ``,
    ...[...byPrincipal.entries()].sort((a, b) => b[1] - a[1]).map(([p, n]) => `- ${p} — ${n} _(declared, not verified)_`),
    ``,
    `## Integrity`,
    ``,
    broken.length ? broken.map((s) => `- ✗ ${s.id}: ${s.reason}`).join("\n") : `- ✓ ${sessions.length} chain(s) verified, no broken links`,
    ``,
    calls.length ? `Peak hour (UTC): ${String(peakHour).padStart(2, "0")}:00 with ${byHour[peakHour]} calls.` : `No tool calls in window.`,
    ``,
    `_Arguments and results are hashed, never stored. See SPEC.md._`,
  ];
  return lines.join("\n");
}

/** Append every session's chain head to a checkpoints file that is itself hash-chained. */
export function anchor({ home = witnessHome() } = {}) {
  const file = path.join(home, "checkpoints.jsonl");
  mkdirSync(home, { recursive: true, mode: 0o700 });
  const existing = existsSync(file) ? readFileSync(file, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)) : [];
  const chain = verifyChain(existing);
  if (!chain.ok) return { file, ok: false, reason: `checkpoint chain broken: ${chain.reason}`, appended: 0 };
  let prev = existing.at(-1)?.hash ?? GENESIS;
  let seq = existing.length;
  const seen = new Map(existing.map((c) => [c.session, c.head]));
  let appended = 0;
  for (const sessionFile of listSessionFiles()) {
    const records = readRecords(sessionFile);
    const head = records.at(-1)?.hash;
    const id = records[0]?.session ?? path.basename(sessionFile, ".jsonl");
    if (!head || seen.get(id) === head) continue;
    const record = sealRecord({ v: "0.1", seq, ts: new Date().toISOString(), event: "checkpoint", session: id, head, records: records.length, verified: verifyChain(records).ok }, prev);
    appendFileSync(file, `${JSON.stringify(record)}\n`, { mode: 0o600 });
    prev = record.hash; seq += 1; appended += 1; seen.set(id, head);
  }
  return { file, ok: true, appended, total: seq };
}
