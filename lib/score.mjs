// witness score: label every call from the stream, Brier-score each judge, rank, rotate. Format v0.2, see SPEC-0.2.md sections 3 and 4.
// Readers append only. Labels go to judge/<session>.jsonl. Score and rotation records go to judge/j_scoreboard.jsonl.
import { existsSync } from "node:fs";
import path from "node:path";
import { parseSince } from "./analyze.mjs";
import { JudgmentLog, judgeDir, readJudgments, verifyJudgments } from "./judge.mjs";
import { verifyChain } from "./record.mjs";
import { listSessionFiles, logDir, readRecords, witnessHome } from "./session-log.mjs";

export const SCOREBOARD = "j_scoreboard";
export const DEFAULT_TERM = { events: 1000, days: 30 };
const DAY_MS = 86400e3;
const PRECEDENCE = ["clean", "flagged", "overridden", "refused"];
const MAX_DIRECTOR_CLASSES = 3;

/**
 * Group tool_call records into calls.
 * A held call can appear as two tool_call records with the same args_sha256: one written by the council
 * before the votes, one written by the recorder when the call runs. Records with the same args_sha256
 * inside one session are one call for labeling. The earliest seq is the call_seq. `alias` maps every
 * tool_call seq of the group to that call_seq, so a vote, grant, override, refusal, tool_result or
 * judge finding that names either seq lands on the same call.
 */
function groupCalls(sessionRecords) {
  const calls = new Map(); // call_seq -> { call_seq, tool, ts }
  const alias = new Map(); // any tool_call seq -> call_seq
  const byDigest = new Map();
  const ordered = sessionRecords.filter((r) => r.event === "tool_call").sort((a, b) => a.seq - b.seq);
  for (const r of ordered) {
    const key = r.args_sha256 ?? `seq:${r.seq}`;
    const first = byDigest.get(key);
    if (first === undefined) {
      byDigest.set(key, r.seq);
      calls.set(r.seq, { call_seq: r.seq, tool: r.tool ?? "?", ts: r.ts });
      alias.set(r.seq, r.seq);
    } else {
      alias.set(r.seq, first);
    }
  }
  return { calls, alias };
}

function sessionOf(records) {
  return records.find((r) => typeof r.session === "string")?.session ?? null;
}

/**
 * outcome_label bodies, one per call. Precedence refused > overridden > flagged > clean.
 * Pass `session` from the file name. Record content is not trusted for the id: a tampered seq 0 could
 * otherwise rename the session and hide a tampered verdict. The record field is a fallback for callers without a file.
 */
export function labelCalls(sessionRecords, judgmentRecords = [], { session = sessionOf(sessionRecords) } = {}) {
  const { calls, alias } = groupCalls(sessionRecords);
  const state = new Map();
  for (const seq of calls.keys()) state.set(seq, { label: "clean", cancel: false, results: [], judges: [], overrides: [], refusals: [] });
  const at = (seq) => (Number.isInteger(seq) && alias.has(seq) ? state.get(alias.get(seq)) : null);
  const raise = (s, label) => { if (PRECEDENCE.indexOf(label) > PRECEDENCE.indexOf(s.label)) s.label = label; };

  for (const r of sessionRecords) {
    const s = at(r.call_seq);
    if (!s) continue;
    if (r.event === "tool_result") s.results.push(r.seq);
    else if (r.event === "override") {
      s.overrides.push(r.seq);
      // The latest answer stands.
      s.cancel = r.answer === "cancel";
      raise(s, "overridden");
    } else if (r.event === "refusal") {
      s.refusals.push(r.seq);
      raise(s, "refused");
    }
  }

  for (const j of judgmentRecords) {
    if (j.event !== "judge") continue;
    if (session && j.subject?.session && j.subject.session !== session) continue;
    if (j.verdict === "tampered") {
      // A broken chain makes every record suspect, so subject.range is ignored: every call is flagged.
      for (const s of state.values()) { s.judges.push(j.seq); raise(s, "flagged"); }
      continue;
    }
    for (const f of j.findings ?? []) {
      if (f?.severity !== "warn" && f?.severity !== "block") continue;
      const s = at(f.call_seq);
      if (!s) continue;
      if (!s.judges.includes(j.seq)) s.judges.push(j.seq);
      raise(s, "flagged");
    }
  }

  const out = [];
  for (const [seq, s] of [...state].sort((a, b) => a[0] - b[0])) {
    const y = s.label === "flagged" || s.label === "refused" || (s.label === "overridden" && s.cancel) ? 1 : 0;
    // Session seqs (tool_result, override, refusal) and judgment chain seqs (judge) stay apart.
    const evidence = { session: [...s.results, ...s.overrides, ...s.refusals].sort((a, b) => a - b), judgment: s.judges };
    out.push({ event: "outcome_label", subject: { session, call_seq: seq }, label: s.label, y, evidence });
  }
  return out;
}

export function decayWeight(ageDays, halfLifeDays = 14) {
  return 0.5 ** (Math.max(0, ageDays) / halfLifeDays);
}

/** Accept a Map, a plain object keyed by session, or an array of record arrays. Judgment chains map by subject. */
function toSessionMap(input, judgment = false) {
  if (!input) return new Map();
  if (input instanceof Map) return input;
  if (Array.isArray(input)) {
    const map = new Map();
    for (const records of input) {
      if (!records?.length) continue;
      const key = judgment ? records.find((r) => r.subject?.session)?.subject.session ?? sessionOf(records)?.replace(/^j_/, "") : sessionOf(records);
      if (key) map.set(key, [...(map.get(key) ?? []), ...records]);
    }
    return map;
  }
  return new Map(Object.entries(input));
}

function toMs(value, fallback) {
  if (value === undefined || value === null) return fallback;
  if (typeof value === "number") return value;
  const t = Date.parse(value);
  return Number.isNaN(t) ? fallback : t;
}

/**
 * Assigned votes per session. Assignment is the set of grant.votes seqs; a vote record no grant names is ignored.
 * An assigned vote with p_unsafe null is an abstention: it counts as 0.5 and is in n.
 * An assigned vote with any other p_unsafe outside [0, 1] is malformed: it is not scored, not in n, and counted in `malformed`.
 * If the council writes two votes from one judge on one call, the latest assigned one counts.
 */
function assignedVotes(sessionRecords) {
  const { calls, alias } = groupCalls(sessionRecords);
  const bySeq = new Map(sessionRecords.map((r) => [r.seq, r]));
  const picked = new Map(); // `${judge}\u0000${call_seq}` -> vote
  for (const g of sessionRecords) {
    if (g.event !== "grant" || !Array.isArray(g.votes)) continue;
    for (const vs of g.votes) {
      const v = bySeq.get(vs);
      if (!v || v.event !== "vote" || typeof v.judge?.id !== "string") continue;
      const callSeq = alias.get(v.call_seq);
      if (callSeq === undefined) continue;
      const key = `${v.judge.id}\u0000${callSeq}`;
      const prior = picked.get(key);
      if (!prior || prior.seq < v.seq) picked.set(key, v);
    }
  }
  return [...picked.values()].map((v) => {
    const callSeq = alias.get(v.call_seq);
    const abstain = v.p_unsafe === null;
    const malformed = !abstain && !(typeof v.p_unsafe === "number" && v.p_unsafe >= 0 && v.p_unsafe <= 1);
    return { judge_id: v.judge.id, call_seq: callSeq, tool: calls.get(callSeq).tool, ts: v.ts ?? calls.get(callSeq).ts, p: abstain || malformed ? 0.5 : v.p_unsafe, abstain, malformed };
  });
}

/** score bodies per judge per event_class plus `*`. n counts every scored assigned vote, abstentions included, malformed votes excluded. */
export function brierScores({ sessions, judgments, since, until, halfLifeDays = 14 } = {}) {
  const untilMs = toMs(until, Date.now());
  const sinceMs = toMs(since, 0);
  const sessionMap = toSessionMap(sessions);
  const judgmentMap = toSessionMap(judgments, true);
  const acc = new Map();
  const bump = (judgeId, eventClass, w, err, v) => {
    const key = `${judgeId}\u0000${eventClass}`;
    const a = acc.get(key) ?? { judge_id: judgeId, event_class: eventClass, n: 0, wsum: 0, esum: 0, abstentions: 0, malformed: 0 };
    if (v.malformed) a.malformed += 1;
    else { a.n += 1; a.wsum += w; a.esum += w * err; if (v.abstain) a.abstentions += 1; }
    acc.set(key, a);
  };
  for (const [session, records] of sessionMap) {
    const labels = labelCalls(records, judgmentMap.get(session) ?? [], { session });
    const y = new Map(labels.map((l) => [l.subject.call_seq, l.y]));
    for (const v of assignedVotes(records)) {
      if (!y.has(v.call_seq)) continue;
      const t = toMs(v.ts, untilMs);
      if (t < sinceMs || t > untilMs) continue;
      const w = decayWeight((untilMs - t) / DAY_MS, halfLifeDays);
      const err = (v.p - y.get(v.call_seq)) ** 2;
      bump(v.judge_id, v.tool, w, err, v);
      bump(v.judge_id, "*", w, err, v);
    }
  }
  const window = { since: new Date(sinceMs).toISOString(), until: new Date(untilMs).toISOString() };
  return [...acc.values()]
    .map((a) => ({ event: "score", judge_id: a.judge_id, event_class: a.event_class, n: a.n, brier: a.wsum > 0 ? a.esum / a.wsum : 0, abstentions: a.abstentions, malformed: a.malformed, window }))
    .sort((a, b) => a.event_class.localeCompare(b.event_class) || a.brier - b.brier || a.judge_id.localeCompare(b.judge_id));
}

/**
 * Per event_class: ascending brier order and roles. Rank counts only judges with n >= minN.
 * Lowest ranked brier is director, the next two are manager, the rest worker (unranked judges are worker).
 * No judge_id is director in more than 3 tool classes: the extra classes, highest brier first, pass the seat down.
 * The `*` class is an aggregate, so it does not count toward the cap and its director is never demoted.
 */
export function rankJudges(scores, { minN = 20 } = {}) {
  const classes = new Map();
  for (const s of scores) {
    if (!classes.has(s.event_class)) classes.set(s.event_class, []);
    classes.get(s.event_class).push(s);
  }
  const eligible = new Map();
  for (const [cls, rows] of classes) {
    rows.sort((a, b) => a.brier - b.brier || a.judge_id.localeCompare(b.judge_id));
    eligible.set(cls, rows.filter((r) => r.n >= minN));
  }
  const blocked = new Map([...classes.keys()].map((c) => [c, new Set()]));
  let directors;
  for (;;) {
    directors = new Map();
    for (const [cls, rows] of eligible) {
      const d = rows.find((r) => !blocked.get(cls).has(r.judge_id));
      if (d) directors.set(cls, d);
    }
    const held = new Map();
    for (const [cls, d] of directors) if (cls !== "*") held.set(d.judge_id, [...(held.get(d.judge_id) ?? []), { cls, brier: d.brier }]);
    let changed = false;
    for (const [judgeId, seats] of held) {
      if (seats.length <= MAX_DIRECTOR_CLASSES) continue;
      seats.sort((a, b) => b.brier - a.brier || a.cls.localeCompare(b.cls));
      for (const seat of seats.slice(0, seats.length - MAX_DIRECTOR_CLASSES)) { blocked.get(seat.cls).add(judgeId); changed = true; }
    }
    if (!changed) break;
  }
  const out = [];
  for (const [cls, rows] of [...classes].sort((a, b) => a[0].localeCompare(b[0]))) {
    const ranked = eligible.get(cls);
    const director = directors.get(cls)?.judge_id ?? null;
    const managers = new Set(ranked.filter((r) => r.judge_id !== director).slice(0, 2).map((r) => r.judge_id));
    const order = rows.map((r) => {
      const idx = ranked.indexOf(r);
      const role = r.judge_id === director ? "director" : managers.has(r.judge_id) ? "manager" : "worker";
      return { judge_id: r.judge_id, event_class: cls, n: r.n, brier: r.brier, rank: idx === -1 ? null : idx + 1, role };
    });
    out.push({ event_class: cls, order });
  }
  return out;
}

/**
 * rotation bodies for judges that reached their term in their current role.
 * events: n scored in this run's window. days: since the judge's first score record for the class in the scoreboard chain.
 * A judge with a rotation already on record for the class is not rotated again. successor is null in v0.2.
 */
export function rotations({ scores, judgments = [], term = DEFAULT_TERM, now = Date.now(), minN = 20 } = {}) {
  const nowMs = toMs(now, Date.now());
  const firstSeen = new Map();
  const rotated = new Set();
  for (const r of judgments) {
    const key = `${r.judge_id}\u0000${r.event_class}`;
    if (r.event === "score") { const t = toMs(r.ts, nowMs); if (!firstSeen.has(key) || t < firstSeen.get(key)) firstSeen.set(key, t); }
    if (r.event === "rotation") rotated.add(key);
  }
  const out = [];
  for (const { order } of rankJudges(scores, { minN })) {
    for (const row of order) {
      const key = `${row.judge_id}\u0000${row.event_class}`;
      if (rotated.has(key)) continue;
      const days = (nowMs - (firstSeen.get(key) ?? nowMs)) / DAY_MS;
      const byEvents = Number.isFinite(term.events) && row.n >= term.events;
      const byDays = Number.isFinite(term.days) && days >= term.days;
      if (!byEvents && !byDays) continue;
      out.push({ event: "rotation", judge_id: row.judge_id, role: row.role, event_class: row.event_class, term: { events: byEvents ? term.events : null, days: byDays ? term.days : null }, successor: null });
    }
  }
  return out;
}

function parseDays(text, fallback) {
  if (typeof text === "number") return text;
  const m = /^(\d+(?:\.\d+)?)([hdw])?$/.exec(String(text ?? ""));
  if (!m) return fallback;
  return Number(m[1]) * ({ h: 1 / 24, d: 1, w: 7 }[m[2] ?? "d"]);
}

function sameLabel(a, b) {
  return a && a.label === b.label && a.y === b.y && JSON.stringify(a.evidence) === JSON.stringify(b.evidence);
}

/** The scoreboard chain: file judge/j_scoreboard.jsonl, records carry session `j_scoreboard`. */
function scoreboardLog(dir) {
  const log = new JudgmentLog({ subject: SCOREBOARD, dir });
  log.session = SCOREBOARD;
  return log;
}

/**
 * Read every session chain under log/ and every judgment chain under judge/. Score sessions that have a
 * judgment chain or at least one vote. Append outcome_label records to judge/<session>.jsonl (a label equal
 * to the latest one on record for that call is not written again), then score and rotation records to the
 * scoreboard chain. Returns the leaderboard rows: { judge_id, event_class, n, brier, rank, role }.
 */
export function runScore({ home = witnessHome(), since = "30d", halfLife = "14d", term = DEFAULT_TERM, now = Date.now(), minN = 20, onWarn = () => {} } = {}) {
  const dir = judgeDir(home);
  const halfLifeDays = parseDays(halfLife, 14);
  const sinceMs = typeof since === "number" ? since : parseSince(since, now);
  const sessions = new Map();
  const judgments = new Map();
  for (const file of listSessionFiles(logDir(home))) {
    const session = path.basename(file, ".jsonl");
    if (session === SCOREBOARD) continue;
    const records = readRecords(file);
    const hasJudgments = existsSync(path.join(dir, `${session}.jsonl`));
    if (!hasJudgments && !records.some((r) => r.event === "vote")) continue;
    let chain = [];
    if (hasJudgments) {
      chain = readJudgments(session, home);
      if (!verifyJudgments(chain).ok) { onWarn(`judgment chain ${session}: broken, session skipped`); continue; }
    }
    const judgedTampered = chain.some((r) => r.event === "judge" && r.verdict === "tampered");
    if (!judgedTampered && !verifyChain(records).ok) onWarn(`session ${session}: chain broken; run witness judge on it for a tampered label`);
    sessions.set(session, records);
    judgments.set(session, chain);
  }

  for (const [session, records] of sessions) {
    const chain = judgments.get(session);
    const latest = new Map();
    for (const r of chain) if (r.event === "outcome_label") latest.set(r.subject?.call_seq, r);
    const labels = labelCalls(records, chain, { session });
    const fresh = labels.filter((l) => !sameLabel(latest.get(l.subject.call_seq), l));
    if (!fresh.length) continue;
    const log = new JudgmentLog({ subject: session, dir });
    for (const label of fresh) chain.push(log.append(label));
  }

  const scores = brierScores({ sessions, judgments, since: sinceMs, until: now, halfLifeDays });
  const board = scoreboardLog(dir);
  const history = readJudgments(SCOREBOARD, home);
  const rotationBodies = rotations({ scores, judgments: history, term, now, minN });
  for (const s of scores) board.append(s);
  for (const r of rotationBodies) board.append(r);
  return rankJudges(scores, { minN }).flatMap((c) => c.order);
}
