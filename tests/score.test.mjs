import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { judgeAdapter, readJudgments, runJudge, verifyJudgments } from "../lib/judge.mjs";
import { GENESIS, sealRecord } from "../lib/record.mjs";
import { brierScores, decayWeight, labelCalls, rankJudges, rotations, runScore } from "../lib/score.mjs";

const bin = new URL("../bin/witness.mjs", import.meta.url).pathname;
const DAY = 86400e3;
const NOW = Date.parse("2026-10-06T12:00:00.000Z");

function run(args, env = {}) {
  return new Promise((resolve) => {
    const p = spawn(process.execPath, [bin, ...args], { env: { ...process.env, ...env } });
    let out = ""; let err = "";
    p.stdout.on("data", (c) => { out += c; }); p.stderr.on("data", (c) => { err += c; });
    p.on("exit", (code) => resolve({ code, out, err }));
  });
}

// Seal events into one chain. An event may carry its own ts; seq is its index.
function seal(session, events, { v = "0.2", ts = new Date(NOW).toISOString() } = {}) {
  let prev = GENESIS;
  return events.map((e, seq) => { const r = sealRecord({ v, seq, ts, session, ...e }, prev); prev = r.hash; return r; });
}

const call = (tool, digest, rpc) => ({ event: "tool_call", rpc_id: rpc, tool, args_sha256: digest.repeat(64), args_bytes: 10, actor: "unknown", principal: null, server: { name: "fake" } });
const result = (tool, callSeq, rpc) => ({ event: "tool_result", rpc_id: rpc, tool, call_seq: callSeq, outcome: { status: "ok", ms: 1 } });
const vote = (callSeq, judgeId, p, extra = {}) => ({ event: "vote", call_seq: callSeq, rpc_id: callSeq, judge: { id: judgeId, model: "m", vendor: "stub", view: "metadata" }, p_unsafe: p, max_caps: ["read"], reason: "r", ms: 1, ...extra });

/**
 * Build a session from call specs: { tool, refuse, votes: [{ judge, p, ts, assigned }] }.
 * Each call is tool_call, votes, grant (naming the assigned vote seqs), then refusal or tool_result.
 */
function buildSession(session, specs) {
  const events = [{ event: "session_start", actor: "unknown", principal: { as: "t", source: "flag", verified: false }, server: { name: "fake", cmd_sha256: "0".repeat(64) }, pid: 1 }];
  specs.forEach((spec, i) => {
    const callSeq = events.length;
    events.push(call(spec.tool, String(i % 10), i));
    const assigned = [];
    for (const v of spec.votes ?? []) {
      if (v.assigned !== false) assigned.push(events.length);
      events.push(vote(callSeq, v.judge, v.p, v.ts ? { ts: v.ts } : {}));
    }
    events.push({ event: "grant", call_seq: callSeq, requested: ["read"], granted: spec.refuse ? [] : ["read"], decision: spec.refuse ? "refuse" : "run", votes: assigned, veto: null });
    if (spec.refuse) events.push({ event: "refusal", call_seq: callSeq, indicator: { kind: "tool", sha256: "a".repeat(64) }, reason: "refused" });
    else events.push(result(spec.tool, callSeq, i));
  });
  return seal(session, events);
}

async function writeChain(home, sub, name, records) {
  await mkdir(path.join(home, sub), { recursive: true });
  await writeFile(path.join(home, sub, `${name}.jsonl`), records.map((r) => JSON.stringify(r)).join("\n") + "\n");
}

test("score labels: clean, flagged by judge, overridden cancel y 1, refused wins, held call merged, tampered flags all", () => {
  const session = seal("s_label001", [
    { event: "session_start" },
    call("read_file", "1", 1), result("read_file", 1, 1), // 1 clean
    call("fetch", "2", 2), result("fetch", 3, 2), // 3 flagged by a warn finding
    call("delete", "3", 3), vote(5, "j1", 0.8), { event: "grant", call_seq: 5, requested: ["delete"], granted: [], decision: "hold", votes: [6], veto: "j1" },
    { event: "override", call_seq: 5, grant_seq: 7, answer: "cancel", by: { as: "h", source: "flag" } }, // 5 overridden, cancel
    call("exec", "4", 4), vote(9, "j1", 0.9), { event: "grant", call_seq: 9, requested: ["exec"], granted: [], decision: "refuse", votes: [10], veto: "j1" },
    { event: "refusal", call_seq: 9, indicator: { kind: "tool", sha256: "b".repeat(64) }, reason: "no" }, // 9 refused, also judge block
    call("write_file", "5", 5), vote(13, "j1", 0.6), { event: "grant", call_seq: 13, requested: ["write"], granted: [], decision: "hold", votes: [14], veto: "j1" },
    { event: "override", call_seq: 13, grant_seq: 15, answer: "proceed", by: { as: "h", source: "flag" } },
    call("write_file", "5", 5), result("write_file", 17, 5), // the recorder's copy of call 13
  ]);
  const judge = seal("j_s_label001", [{ event: "judge", subject: { session: "s_label001", range: [0, 18], head: "x" }, judge: { id: "jj", model: "m", vendor: "stub", view: "metadata" }, verdict: "flagged", findings: [{ call_seq: 3, severity: "warn", note: "n" }, { call_seq: 9, severity: "block", note: "n" }, { call_seq: 1, severity: "info", note: "n" }], chain_ok: true, ms: 1 }]);
  const labels = labelCalls(session, judge);
  const by = Object.fromEntries(labels.map((l) => [l.subject.call_seq, l]));
  assert.deepEqual(Object.keys(by).map(Number), [1, 3, 5, 9, 13], "same args_sha256 is one call at the earliest seq");
  assert.deepEqual(by[1], { event: "outcome_label", subject: { session: "s_label001", call_seq: 1 }, label: "clean", y: 0, evidence: { session: [2], judgment: [] } });
  assert.deepEqual([by[3].label, by[3].y, by[3].evidence], ["flagged", 1, { session: [4], judgment: [0] }]);
  assert.deepEqual([by[5].label, by[5].y, by[5].evidence], ["overridden", 1, { session: [8], judgment: [] }]);
  assert.deepEqual([by[9].label, by[9].y, by[9].evidence], ["refused", 1, { session: [12], judgment: [0] }]);
  assert.deepEqual([by[13].label, by[13].y, by[13].evidence], ["overridden", 0, { session: [16, 18], judgment: [] }]);

  const plain = seal("s_label002", [{ event: "session_start" }, call("a", "1", 1), result("a", 1, 1), call("b", "2", 2), result("b", 3, 2)]);
  const tampered = seal("j_s_label002", [{ event: "judge", subject: { session: "s_label002", range: [0, 1], head: "x" }, judge: { id: "jj" }, verdict: "tampered", findings: [], chain_ok: false, ms: 0 }]);
  const t = labelCalls(plain, tampered, { session: "s_label002" });
  assert.deepEqual(t.map((l) => [l.label, l.y]), [["flagged", 1], ["flagged", 1]], "calls outside range [0, 1] are flagged too");
  assert.deepEqual(t[0].evidence, { session: [2], judgment: [0] });
});

test("score brier: 0.9 on y 1 and 0.1 on y 0 gives 0.01; abstention counts 0.5; decay halves weight at one half-life", () => {
  const old = new Date(NOW - 14 * DAY).toISOString();
  const session = buildSession("s_brier001", [
    { tool: "exec", refuse: true, votes: [{ judge: "sharp", p: 0.9 }, { judge: "abstainer", p: null }, { judge: "decayed", p: 1 }, { judge: "broken", p: 1.7 }] },
    { tool: "exec", votes: [{ judge: "sharp", p: 0.1 }, { judge: "decayed", p: 1, ts: old }] },
  ]);
  const scores = brierScores({ sessions: [session], judgments: [], since: 0, until: NOW, halfLifeDays: 14 });
  const get = (id, cls = "*") => scores.find((s) => s.judge_id === id && s.event_class === cls);
  assert.equal(get("sharp").n, 2);
  assert.ok(Math.abs(get("sharp").brier - 0.01) < 1e-12);
  assert.ok(Math.abs(get("sharp", "exec").brier - 0.01) < 1e-12);
  assert.equal(get("abstainer").abstentions, 1);
  assert.equal(get("abstainer").n, 1);
  assert.equal(get("abstainer").brier, 0.25);
  assert.deepEqual([get("broken").n, get("broken").malformed, get("broken").abstentions], [0, 1, 0], "a malformed vote is not scored and not in n");
  assert.equal(get("sharp").malformed, 0);
  assert.equal(decayWeight(14, 14), 0.5);
  // err 0 at age 0 (weight 1), err 1 at age 14 days (weight 0.5): 0.5 / 1.5.
  assert.ok(Math.abs(get("decayed").brier - 1 / 3) < 1e-12);
  assert.equal(get("sharp").event, "score");
  assert.deepEqual(get("sharp").window, { since: new Date(0).toISOString(), until: new Date(NOW).toISOString() });
});

test("score assignment: a vote on a call the judge was not assigned to is ignored", () => {
  const session = buildSession("s_assign01", [{ tool: "fetch", votes: [{ judge: "named", p: 0.2 }, { judge: "stray", p: 0.9, assigned: false }] }]);
  const scores = brierScores({ sessions: [session], since: 0, until: NOW });
  assert.ok(scores.some((s) => s.judge_id === "named"));
  assert.ok(!scores.some((s) => s.judge_id === "stray"));
});

test("score ranking: director is lowest brier with n >= 20, next two manager; no judge directs more than 3 classes", () => {
  const row = (judge_id, event_class, brier, n = 25) => ({ judge_id, event_class, brier, n });
  const [a] = rankJudges([row("j1", "a", 0.05), row("j2", "a", 0.01, 5), row("j3", "a", 0.1, 30), row("j4", "a", 0.2, 20), row("j5", "a", 0.3, 40)]);
  const roles = Object.fromEntries(a.order.map((r) => [r.judge_id, [r.rank, r.role]]));
  assert.deepEqual(roles, { j1: [1, "director"], j2: [null, "worker"], j3: [2, "manager"], j4: [3, "manager"], j5: [4, "worker"] });

  const scores = [];
  ["c1", "c2", "c3", "c4", "c5"].forEach((c, i) => { scores.push(row("X", c, 0.01 * (i + 1)), row("Y", c, 0.06)); });
  scores.push(row("X", "*", 0.03), row("Y", "*", 0.06));
  const ranked = rankJudges(scores);
  const director = Object.fromEntries(ranked.map((c) => [c.event_class, c.order.find((r) => r.role === "director").judge_id]));
  assert.deepEqual(director, { "*": "X", c1: "X", c2: "X", c3: "X", c4: "Y", c5: "Y" }, "the * class does not count toward the cap");
  assert.equal(ranked.find((c) => c.event_class === "c5").order.find((r) => r.judge_id === "X").role, "manager");
  assert.equal(ranked.find((c) => c.event_class === "c5").order.find((r) => r.judge_id === "X").rank, 1, "rank stays the brier order");
});

test("score rotation: fires at term.events, again by term.days, never twice for one judge and class", () => {
  const scores = [{ judge_id: "J", event_class: "fetch", n: 3, brier: 0.1 }, { judge_id: "K", event_class: "fetch", n: 2, brier: 0.2 }];
  const fired = rotations({ scores, judgments: [], term: { events: 3, days: 365 }, now: NOW });
  assert.deepEqual(fired, [{ event: "rotation", judge_id: "J", role: "worker", event_class: "fetch", term: { events: 3, days: null }, successor: null }]);
  assert.deepEqual(rotations({ scores, judgments: fired, term: { events: 3, days: 365 }, now: NOW }), []);
  const history = [{ event: "score", judge_id: "K", event_class: "fetch", ts: new Date(NOW - 31 * DAY).toISOString() }];
  const byDays = rotations({ scores, judgments: [...fired, ...history], term: { events: 100, days: 30 }, now: NOW });
  assert.deepEqual(byDays.map((r) => [r.judge_id, r.term]), [["K", { events: null, days: 30 }]]);
});

test("score CLI: prints the leaderboard, exit 0; labels and j_scoreboard chains verify; a rerun adds no duplicate labels", async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), "witness-score-"));
  const ts = new Date().toISOString();
  const session = buildSession("s_cli00001", [
    { tool: "exec", refuse: true, votes: [{ judge: "sharp", p: 0.9, ts }] },
    { tool: "exec", votes: [{ judge: "sharp", p: 0.1, ts }] },
  ]);
  await writeChain(home, "log", "s_cli00001", session);
  const first = await run(["score"], { WITNESS_HOME: home });
  assert.equal(first.code, 0, first.err);
  assert.match(first.out, /^judge_id\s+event_class\s+n\s+brier\s+rank\s+role\n/);
  assert.match(first.out, /sharp\s+\*\s+2\s+0\.0100\s+-\s+worker/);
  assert.match(first.out, /sharp\s+exec\s+2\s+0\.0100\s+-\s+worker/);
  const board = readJudgments("j_scoreboard", home);
  assert.equal(verifyJudgments(board).ok, true);
  assert.deepEqual(board.map((r) => [r.event, r.session, r.v]), [["score", "j_scoreboard", "0.2"], ["score", "j_scoreboard", "0.2"]]);
  const labels = readJudgments("s_cli00001", home);
  assert.equal(verifyJudgments(labels).ok, true);
  assert.deepEqual(labels.map((r) => [r.event, r.label, r.y]), [["outcome_label", "refused", 1], ["outcome_label", "clean", 0]]);
  assert.equal(first.err, "", "an intact chain gives no warning");

  const json = await run(["score", "--since", "30d", "--half-life", "14d", "--json"], { WITNESS_HOME: home });
  assert.equal(json.code, 0, json.err);
  const rows = json.out.trim().split("\n").map((l) => JSON.parse(l));
  assert.deepEqual(Object.keys(rows[0]).sort(), ["brier", "event_class", "judge_id", "n", "rank", "role"]);
  assert.equal(readJudgments("s_cli00001", home).length, 2, "unchanged labels are not appended again");
  assert.equal(verifyJudgments(readJudgments("j_scoreboard", home)).ok, true);
  assert.equal(readJudgments("j_scoreboard", home).length, 4);

  const direct = runScore({ home, term: { events: 2, days: 365 } });
  assert.equal(direct.length, 2);
  const rotated = readJudgments("j_scoreboard", home).filter((r) => r.event === "rotation");
  assert.deepEqual(rotated.map((r) => [r.judge_id, r.event_class, r.term.events, r.successor]), [["sharp", "*", 2, null], ["sharp", "exec", 2, null]]);
  await rm(home, { recursive: true, force: true });
});

test("score: an edited session field in seq 0 cannot hide a tampered verdict; every label is flagged and no warning prints", async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), "witness-score-"));
  const records = buildSession("s_tamp0002", [{ tool: "read_file", votes: [{ judge: "j1", p: 0.1 }] }, { tool: "list_dir", votes: [{ judge: "j1", p: 0.2 }] }]);
  records[0].session = "s_other000";
  await writeChain(home, "log", "s_tamp0002", records);
  const judged = await runJudge({ subject: "s_tamp0002", adapter: judgeAdapter({ vendor: "stub" }), home, judge: { vendor: "stub", model: "stub" } });
  assert.equal(judged.verdict, "tampered");
  const warnings = [];
  runScore({ home, since: 0, now: NOW, onWarn: (m) => warnings.push(m) });
  const labels = readJudgments("s_tamp0002", home).filter((r) => r.event === "outcome_label");
  assert.equal(labels.length, 2);
  assert.ok(labels.every((l) => l.label === "flagged" && l.y === 1 && l.subject.session === "s_tamp0002"));
  assert.deepEqual(warnings, [], "the tampered judge record already covers the broken chain");
  await rm(home, { recursive: true, force: true });
});

test("score: over the council fixture after a stub judge run, the refused Write is labeled refused with y 1", async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), "witness-score-"));
  const fixture = new URL("./fixtures/sessions/council.jsonl", import.meta.url);
  await mkdir(path.join(home, "log"), { recursive: true });
  await writeFile(path.join(home, "log", "s_c0c11000.jsonl"), await readFile(fixture, "utf8"));
  await runJudge({ subject: "s_c0c11000", adapter: judgeAdapter({ vendor: "stub" }), home, judge: { vendor: "stub", model: "stub", view: "full" } });
  const rows = runScore({ home, since: 0, now: NOW });
  const write = readJudgments("s_c0c11000", home).find((r) => r.event === "outcome_label" && r.subject.call_seq === 8);
  assert.equal(write.label, "refused");
  assert.equal(write.y, 1);
  assert.deepEqual(write.evidence.session, [13, 14]);
  assert.ok(rows.some((r) => r.judge_id === "anthropic:claude-haiku" && r.event_class === "Write" && r.n === 1));
  await rm(home, { recursive: true, force: true });
});
