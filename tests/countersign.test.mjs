import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createPublicKey, verify as edVerify } from "node:crypto";
import fs, { copyFileSync, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { mkdtemp, rm } from "node:fs/promises";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { CHECK_EXIT, checkSession } from "../lib/check.mjs";
import { checkHead, headDigest, headsFile, loadKey, sealSession, signHead } from "../lib/heads.mjs";
import { fingerprintOf, keygen, pinnedKey } from "../lib/keys.mjs";
import { checkReceipt, countersignSession, notaryPaths, receiptShape, receiptsFile, startNotaryServer, verifyNotaryLog } from "../lib/notary.mjs";
import { canonical, sealRecord } from "../lib/record.mjs";
import { SessionLog, logDir } from "../lib/session-log.mjs";

const bin = new URL("../bin/witness.mjs", import.meta.url).pathname;
const tempHome = () => mkdtemp(path.join(os.tmpdir(), "witness-countersign-"));
const readLines = (file) => readFileSync(file, "utf8").split("\n").filter(Boolean);
const readJson = (file) => readLines(file).map((line) => JSON.parse(line));
const writeJson = (file, records) => writeFileSync(file, records.map((r) => `${JSON.stringify(r)}\n`).join(""));

function run(args, env = {}, killAfterMs = 10_000) {
  return new Promise((resolve) => {
    const p = spawn(process.execPath, [bin, ...args], { env: { ...process.env, ...env } });
    let out = ""; let err = "";
    const timer = setTimeout(() => p.kill(), killAfterMs);
    p.stdout.on("data", (c) => { out += c; }); p.stderr.on("data", (c) => { err += c; });
    p.on("exit", (code) => { clearTimeout(timer); resolve({ code, out, err }); });
  });
}

/** Append n tool_call records to log/<session>.jsonl with the real writer. */
function writeSession(home, session, n, from = 0) {
  const log = new SessionLog({ session, dir: logDir(home) });
  // SessionLog starts a new chain; continue an existing one by hand.
  try {
    const last = readJson(log.file).at(-1);
    if (last) { log.prev = last.hash; log.seq = last.seq + 1; }
  } catch { /* new file */ }
  for (let i = 0; i < n; i += 1) log.append({ event: "tool_call", rpc_id: from + i, tool: `tool_${from + i}`, args_sha256: "0".repeat(64), args_bytes: 2 });
  return log.file;
}

function trust(fromHome, toHome, keyId) {
  mkdirSync(path.join(toHome, "keys"), { recursive: true, mode: 0o700 });
  copyFileSync(path.join(fromHome, "keys", `${keyId}.pub`), path.join(toHome, "keys", `${keyId}.pub`));
}

/** An operator home with sessions, a notary home with its own key, and a running notary. The operator trusts the notary .pub. */
async function setup(sessions = { s_aaaa0001: 5 }) {
  const op = await tempHome();
  const no = await tempHome();
  const opKey = keygen(op).keyId;
  const noKey = keygen(no).keyId;
  trust(no, op, noKey);
  for (const [session, n] of Object.entries(sessions)) writeSession(op, session, n);
  // Tests that are not about the rate cap must not trip it.
  const notary = await startNotaryServer({ home: no, keyId: noKey, port: 0, limits: { rate: 10_000 } });
  const cleanup = async () => { await notary.close(); await rm(op, { recursive: true, force: true }); await rm(no, { recursive: true, force: true }); };
  return { op, no, opKey, noKey, notary, cleanup };
}

/** An outside party's home: copies of one session's log, heads and receipts, and the notary .pub. Nothing else. */
async function outsider(env, session, { operatorPub = false } = {}) {
  const home = await tempHome();
  for (const [dir, file] of [["log", path.join(logDir(env.op), `${session}.jsonl`)], ["heads", headsFile(session, env.op)], ["receipts", receiptsFile(session, env.op)]]) {
    mkdirSync(path.join(home, dir), { recursive: true });
    copyFileSync(file, path.join(home, dir, `${session}.jsonl`));
  }
  trust(env.no, home, env.noKey);
  if (operatorPub) trust(env.op, home, env.opKey);
  return home;
}

async function post(url, body, headers = {}) {
  const res = await fetch(url, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: typeof body === "string" || body instanceof Uint8Array ? body : JSON.stringify(body) });
  return { status: res.status, text: await res.text(), headers: res.headers };
}

/** Send raw bytes on a fresh socket and resolve with everything the server writes before it closes. */
function rawRequest(port, text, { holdMs = 0 } = {}) {
  return new Promise((resolve) => {
    const socket = net.connect(port, "127.0.0.1");
    let data = "";
    socket.on("data", (c) => { data += c; });
    socket.on("error", () => {});
    socket.on("close", () => resolve(data));
    socket.write(text);
    if (holdMs) setTimeout(() => socket.destroy(), holdMs);
  });
}

test("seal: signs the last record into heads/<session>.jsonl, is idempotent, and seals again as the chain grows", async () => {
  const home = await tempHome();
  const { keyId } = keygen(home);
  writeSession(home, "s_aaaa0001", 3);
  const result = await run(["seal", "s_aaaa0001", "--key", keyId], { WITNESS_HOME: home });
  assert.equal(result.code, 0, result.out + result.err);
  assert.match(result.out, /^SEALED s_aaaa0001 {2}seq 2 /);
  assert.doesNotMatch(result.out + result.err, /PRIVATE KEY/);
  const file = headsFile("s_aaaa0001", home);
  assert.equal(statSync(file).mode & 0o777, 0o600);
  assert.equal(statSync(path.dirname(file)).mode & 0o777, 0o700);
  const [head] = readJson(file);
  const last = readJson(path.join(logDir(home), "s_aaaa0001.jsonl")).at(-1);
  assert.deepEqual(Object.keys(head).sort(), ["alg", "hash", "key_id", "public_key", "records", "seq", "session", "sig", "ts", "type", "v"]);
  assert.equal(head.v, "0.4");
  assert.equal(head.type, "head");
  assert.equal(head.seq, 2);
  assert.equal(head.records, 3);
  assert.equal(head.hash, last.hash);
  assert.equal(head.key_id, keyId);
  assert.equal(checkHead(head), null);
  // The signature is ed25519 over the UTF-8 bytes of canonical(head without sig), checked here with node:crypto alone.
  const { sig, ...body } = head;
  const publicKey = createPublicKey({ key: Buffer.from(head.public_key, "base64"), format: "der", type: "spki" });
  assert.ok(edVerify(null, Buffer.from(canonical(body)), publicKey, Buffer.from(sig, "base64")));
  // A second seal of the same chain appends nothing.
  const again = await run(["seal", "--all", "--key", keyId], { WITNESS_HOME: home });
  assert.equal(again.code, 0);
  assert.match(again.out, /already sealed/);
  assert.equal(readLines(file).length, 1);
  // The chain grows: a new head is appended, the old one stays.
  writeSession(home, "s_aaaa0001", 2, 3);
  assert.equal(sealSession({ session: "s_aaaa0001", keyId, home }).appended, true);
  assert.deepEqual(readJson(file).map((h) => h.seq), [2, 4]);
  // A broken chain is not sealed: exit 3, nothing appended.
  const log = path.join(logDir(home), "s_aaaa0001.jsonl");
  writeFileSync(log, readFileSync(log, "utf8").replace('"tool_1"', '"tool_x"'));
  writeSession(home, "s_aaaa0001", 1, 5);
  const broken = await run(["seal", "s_aaaa0001", "--key", keyId], { WITNESS_HOME: home });
  assert.equal(broken.code, 3, broken.out);
  assert.match(broken.out, /FAIL {3}s_aaaa0001 {2}s_aaaa0001 is broken: hash mismatch at seq 1\. Nothing sealed\./);
  assert.equal(readLines(file).length, 2);
  // A missing key or a session that does not exist is exit 1.
  assert.equal((await run(["seal", "s_aaaa0001", "--key", "k_00000000"], { WITNESS_HOME: home })).code, 1);
  assert.equal((await run(["seal", "s_nope", "--key", keyId], { WITNESS_HOME: home })).code, 1);
  assert.equal((await run(["seal", "--key", keyId], { WITNESS_HOME: home })).code, 1);
  await rm(home, { recursive: true, force: true });
});

test("countersign: the notary appends a signed receipt to its chained log; check passes offline with only copies and public keys", async () => {
  const env = await setup({ s_aaaa0001: 5, s_bbbb0002: 2 });
  try {
    const first = await run(["countersign", env.notary.url, "--all", "--key", env.opKey, "--notary", env.noKey], { WITNESS_HOME: env.op });
    assert.equal(first.code, 0, first.out + first.err);
    assert.match(first.out, /^SIGNED s_aaaa0001 {2}seq 4 {2}receipt k_[0-9a-f]{8} seq \d at /m);
    assert.match(first.out, /^SIGNED s_bbbb0002 {2}seq 1 /m);
    const [receipt] = readJson(receiptsFile("s_aaaa0001", env.op));
    const [head] = readJson(headsFile("s_aaaa0001", env.op));
    assert.deepEqual(Object.keys(receipt).sort(), ["event", "hash", "head", "prev", "seq", "session", "signer", "ts", "v"]);
    assert.equal(receipt.event, "receipt");
    assert.equal(receipt.session, "notary");
    assert.deepEqual(Object.keys(receipt.head).sort(), ["hash", "key_id", "seq", "session", "sha256"]);
    assert.equal(receipt.head.hash, head.hash);
    assert.equal(receipt.head.key_id, env.opKey);
    assert.equal(receipt.signer.key_id, env.noKey);
    assert.equal(statSync(receiptsFile("s_aaaa0001", env.op)).mode & 0o777, 0o600);
    // The notary log holds both receipts as one chain, and it verifies.
    assert.equal(readLines(notaryPaths(env.no).log).length, 2);
    assert.deepEqual(verifyNotaryLog({ home: env.no, keyId: env.noKey }).ok, true);
    const verified = await run(["notary", "verify"], { WITNESS_HOME: env.no });
    assert.equal(verified.code, 0, verified.out);
    assert.match(verified.out, /^OK {3}.*log\.jsonl {2}2 receipts \(signed by k_/);
    // A second run sends nothing.
    const second = await run(["countersign", env.notary.url, "--all", "--key", env.opKey], { WITNESS_HOME: env.op });
    assert.equal(second.code, 0);
    assert.equal(second.out.match(/already countersigned/g).length, 2);
    assert.equal(readLines(notaryPaths(env.no).log).length, 2);
    // An outside party with copies of log, heads, receipts and the notary .pub, and no private key.
    const outside = await outsider(env, "s_aaaa0001", { operatorPub: true });
    const check = await run(["check", "s_aaaa0001", "--notary", env.noKey, "--operator", env.opKey], { WITNESS_HOME: outside });
    assert.equal(check.code, 0, check.out);
    assert.match(check.out, /^OK {3}chain s_aaaa0001: 5 records intact$/m);
    assert.match(check.out, /countersigned by k_[0-9a-f]{8} at .* \(notary seq \d\)$/m);
    assert.match(check.out, /^s_aaaa0001: countersigned through seq 4$/m);
    // The chain grows past the seal: still ok, with a note that the new records are not covered.
    writeSession(env.op, "s_aaaa0001", 2, 5);
    const grown = await outsider(env, "s_aaaa0001");
    const partial = checkSession({ session: "s_aaaa0001", notaryKeyId: env.noKey, home: grown });
    assert.equal(partial.code, CHECK_EXIT.ok);
    assert.equal(partial.covered, 4);
    assert.ok(partial.notes.some((n) => n === "records 5 to 6 are after the last countersigned head and are not covered"));
    // Countersign again: a new head and a new receipt cover the new records.
    const third = await countersignSession({ url: env.notary.url, session: "s_aaaa0001", keyId: env.opKey, notaryKeyId: env.noKey, home: env.op });
    assert.equal(third.sent, true);
    assert.equal(third.verified, true);
    const full = await outsider(env, "s_aaaa0001");
    const all = checkSession({ session: "s_aaaa0001", notaryKeyId: env.noKey, home: full });
    assert.equal(all.code, 0, JSON.stringify(all.failures));
    assert.equal(all.covered, 6);
    for (const dir of [outside, grown, full]) await rm(dir, { recursive: true, force: true });
  } finally {
    await env.cleanup();
  }
});

test("check: a record edited before the sealed seq exits 2; the same edit with the chain rebuilt after it exits 3", async () => {
  const env = await setup();
  try {
    await countersignSession({ url: env.notary.url, session: "s_aaaa0001", keyId: env.opKey, notaryKeyId: env.noKey, home: env.op });
    const home = await outsider(env, "s_aaaa0001");
    const log = path.join(logDir(home), "s_aaaa0001.jsonl");
    const original = readFileSync(log, "utf8");
    writeFileSync(log, original.replace('"tool_2"', '"tool_z"'));
    const plain = await run(["check", "s_aaaa0001", "--notary", env.noKey], { WITNESS_HOME: home });
    assert.equal(plain.code, 2, plain.out);
    assert.match(plain.out, /^FAIL chain s_aaaa0001: hash mismatch at seq 2$/m);
    // Rebuild every hash after the edit, as an administrator with filesystem access could. The chain is intact again,
    // but the record at the sealed seq no longer has the hash the head and the receipt name.
    let prev = "GENESIS";
    const rebuilt = readJson(log).map(({ hash: _h, prev: _p, ...body }) => { const r = sealRecord(body, prev); prev = r.hash; return r; });
    writeJson(log, rebuilt);
    const rechained = await run(["check", "s_aaaa0001", "--notary", env.noKey], { WITNESS_HOME: home });
    assert.equal(rechained.code, 3, rechained.out);
    assert.match(rechained.out, /^OK {3}chain s_aaaa0001: 5 records intact$/m);
    assert.match(rechained.out, /^FAIL head 1 of heads\/s_aaaa0001\.jsonl: the record at seq 4 has hash [0-9a-f]{12}, the head says [0-9a-f]{12}$/m);
    // A truncated chain: the head names a seq past the end.
    writeJson(log, readJson(log).slice(0, 3));
    const short = checkSession({ session: "s_aaaa0001", notaryKeyId: env.noKey, home });
    assert.equal(short.code, CHECK_EXIT.head);
    assert.match(short.failures[0].message, /seq 4 is past the end of the chain \(3 records\)/);
    await rm(home, { recursive: true, force: true });
  } finally {
    await env.cleanup();
  }
});

test("check: a forged head signature exits 4, and the notary refuses the forged head with 422", async () => {
  const env = await setup();
  try {
    await countersignSession({ url: env.notary.url, session: "s_aaaa0001", keyId: env.opKey, notaryKeyId: env.noKey, home: env.op });
    const home = await outsider(env, "s_aaaa0001");
    const file = headsFile("s_aaaa0001", home);
    const [head] = readJson(file);
    // The head moved to an earlier seq and hash, with the old signature kept: the signature no longer covers it.
    const forged = { ...head, seq: 3, hash: readJson(path.join(logDir(home), "s_aaaa0001.jsonl"))[3].hash, records: 4 };
    writeJson(file, [{ ...forged, sig: head.sig }]);
    const result = await run(["check", "s_aaaa0001", "--notary", env.noKey], { WITNESS_HOME: home });
    assert.equal(result.code, 4, result.out);
    assert.match(result.out, /^FAIL head 1 of heads\/s_aaaa0001\.jsonl: the head signature does not verify against k_[0-9a-f]{8}$/m);
    // The receipt now names a head that is not in the file either; the exit code is the first failure's.
    assert.match(result.out, /^FAIL receipt 1 .*which is not in heads\/s_aaaa0001\.jsonl$/m);
    const refused = await post(env.notary.url, { ...forged, sig: head.sig });
    assert.equal(refused.status, 422);
    assert.match(refused.text, /the head signature does not verify/);
    await rm(home, { recursive: true, force: true });
  } finally {
    await env.cleanup();
  }
});

test("check: a head whose key_id does not match its public_key exits 4, and the notary refuses it with 422", async () => {
  const env = await setup();
  try {
    await countersignSession({ url: env.notary.url, session: "s_aaaa0001", keyId: env.opKey, notaryKeyId: env.noKey, home: env.op });
    const home = await outsider(env, "s_aaaa0001");
    const file = headsFile("s_aaaa0001", home);
    const [head] = readJson(file);
    // Signed correctly with the operator key, but naming another key_id.
    const { sig: _sig, ...body } = head;
    const relabeled = signHead({ ...body, key_id: "k_00000000" }, loadKey(env.opKey, env.op));
    writeJson(file, [relabeled]);
    const result = await run(["check", "s_aaaa0001", "--notary", env.noKey], { WITNESS_HOME: home });
    assert.equal(result.code, 4, result.out);
    assert.match(result.out, new RegExp(`^FAIL head 1 of heads/s_aaaa0001\\.jsonl: the head key_id k_00000000 does not match its public_key \\(${env.opKey}\\)$`, "m"));
    const refused = await post(env.notary.url, relabeled);
    assert.equal(refused.status, 422);
    assert.match(refused.text, /does not match its public_key/);
    // --operator names a key the heads were not signed with: exit 4 as well.
    const intact = await outsider(env, "s_aaaa0001", { operatorPub: true });
    const strange = keygen(intact).keyId;
    const wrongOperator = checkSession({ session: "s_aaaa0001", notaryKeyId: env.noKey, operatorKeyId: strange, home: intact });
    assert.equal(wrongOperator.code, CHECK_EXIT.headSignature);
    assert.match(wrongOperator.failures[0].message, new RegExp(`signed by ${env.opKey}, not the --operator key ${strange}`));
    for (const dir of [home, intact]) await rm(dir, { recursive: true, force: true });
  } finally {
    await env.cleanup();
  }
});

test("check: a receipt for a different head exits 6", async () => {
  const env = await setup({ s_aaaa0001: 5, s_bbbb0002: 3 });
  try {
    for (const session of ["s_aaaa0001", "s_bbbb0002"]) await countersignSession({ url: env.notary.url, session, keyId: env.opKey, notaryKeyId: env.noKey, home: env.op });
    const home = await outsider(env, "s_aaaa0001");
    // The receipt of session b, signed and valid on its own, put in place of a's.
    copyFileSync(receiptsFile("s_bbbb0002", env.op), receiptsFile("s_aaaa0001", home));
    const result = await run(["check", "s_aaaa0001", "--notary", env.noKey], { WITNESS_HOME: home });
    assert.equal(result.code, 6, result.out);
    assert.match(result.out, /^FAIL receipt 1 of receipts\/s_aaaa0001\.jsonl: names head [0-9a-f]{12} \(session s_bbbb0002, seq 2\), which is not in heads\/s_aaaa0001\.jsonl$/m);
    // A receipt whose head fields were edited no longer verifies: its hash does not match its content (exit 5 comes first).
    const [receipt] = readJson(receiptsFile("s_aaaa0001", env.op));
    writeJson(receiptsFile("s_aaaa0001", home), [{ ...receipt, head: { ...receipt.head, seq: 3 } }]);
    const edited = checkSession({ session: "s_aaaa0001", notaryKeyId: env.noKey, home });
    assert.equal(edited.code, CHECK_EXIT.receiptSignature);
    assert.match(edited.failures[0].message, /the receipt hash does not match its content/);
    // No receipt at all: exit 7.
    writeFileSync(receiptsFile("s_aaaa0001", home), "");
    assert.equal(checkSession({ session: "s_aaaa0001", notaryKeyId: env.noKey, home }).code, CHECK_EXIT.missing);
    await rm(home, { recursive: true, force: true });
  } finally {
    await env.cleanup();
  }
});

test("check: a receipt checked against the wrong notary key exits 5", async () => {
  const env = await setup();
  try {
    await countersignSession({ url: env.notary.url, session: "s_aaaa0001", keyId: env.opKey, notaryKeyId: env.noKey, home: env.op });
    const home = await outsider(env, "s_aaaa0001", { operatorPub: true });
    // Another trusted key in keys/: the receipt is not signed by it.
    const result = await run(["check", "s_aaaa0001", "--notary", env.opKey], { WITNESS_HOME: home });
    assert.equal(result.code, 5, result.out);
    assert.match(result.out, new RegExp(`^FAIL receipt 1 of receipts/s_aaaa0001\\.jsonl: the receipt is signed by ${env.noKey}, not ${env.opKey}$`, "m"));
    // The right key_id, but its .pub holds another key: not trusted.
    copyFileSync(path.join(home, "keys", `${env.opKey}.pub`), path.join(home, "keys", `${env.noKey}.pub`));
    const swapped = await run(["check", "s_aaaa0001", "--notary", env.noKey], { WITNESS_HOME: home });
    assert.equal(swapped.code, 5, swapped.out);
    assert.match(swapped.out, new RegExp(`^FAIL --notary ${env.noKey}: keys/${env.noKey}\\.pub holds key ${env.opKey}, not ${env.noKey}$`, "m"));
    // No .pub for the notary at all.
    const bare = await tempHome();
    for (const dir of ["log", "heads", "receipts"]) { mkdirSync(path.join(bare, dir)); copyFileSync(path.join(home, dir, "s_aaaa0001.jsonl"), path.join(bare, dir, "s_aaaa0001.jsonl")); }
    assert.equal(checkSession({ session: "s_aaaa0001", notaryKeyId: env.noKey, home: bare }).code, CHECK_EXIT.receiptSignature);
    // A forged notary signature with the right key trusted.
    const good = await outsider(env, "s_aaaa0001");
    const [receipt] = readJson(receiptsFile("s_aaaa0001", good));
    const sig = Buffer.from(receipt.signer.sig, "base64"); sig[0] ^= 1;
    writeJson(receiptsFile("s_aaaa0001", good), [{ ...receipt, signer: { ...receipt.signer, sig: sig.toString("base64") } }]);
    const forged = checkSession({ session: "s_aaaa0001", notaryKeyId: env.noKey, home: good });
    assert.equal(forged.code, CHECK_EXIT.receiptSignature);
    assert.match(forged.failures[0].message, /the receipt has a bad signature/);
    for (const dir of [home, bare, good]) await rm(dir, { recursive: true, force: true });
  } finally {
    await env.cleanup();
  }
});

test("countersign: a receipt that names another head, or has a bad signature, is not stored and exits 3", async () => {
  const env = await setup({ s_aaaa0001: 3, s_bbbb0002: 2 });
  try {
    await countersignSession({ url: env.notary.url, session: "s_bbbb0002", keyId: env.opKey, notaryKeyId: env.noKey, home: env.op });
    const otherReceipt = readLines(receiptsFile("s_bbbb0002", env.op))[0];
    const reply = (text) => async () => new Response(text, { status: 200 });
    await assert.rejects(countersignSession({ url: env.notary.url, session: "s_aaaa0001", keyId: env.opKey, notaryKeyId: env.noKey, home: env.op, fetchImpl: reply(otherReceipt) }), (error) => error.exitCode === 3 && /the receipt head sha256 .* does not match the head .*Nothing stored\./.test(error.message));
    // A real receipt for this head, with one signature byte flipped on the way back.
    const flip = async (url, init) => {
      const r = JSON.parse(await (await fetch(url, init)).text());
      const sig = Buffer.from(r.signer.sig, "base64"); sig[5] ^= 1;
      return new Response(JSON.stringify({ ...r, signer: { ...r.signer, sig: sig.toString("base64") } }), { status: 200 });
    };
    await assert.rejects(countersignSession({ url: env.notary.url, session: "s_aaaa0001", keyId: env.opKey, home: env.op, fetchImpl: flip }), (error) => error.exitCode === 3 && /the receipt has a bad signature\. Nothing stored\./.test(error.message));
    assert.throws(() => readFileSync(receiptsFile("s_aaaa0001", env.op)), { code: "ENOENT" });
    // A notary that answers 422 is exit 1, and nothing is stored.
    await assert.rejects(countersignSession({ url: env.notary.url, session: "s_aaaa0001", keyId: env.opKey, home: env.op, fetchImpl: async () => new Response("no\n", { status: 422 }) }), (error) => error.exitCode === 1 && /HTTP 422/.test(error.message));
  } finally {
    await env.cleanup();
  }
});

test("notary verify: a broken notary log exits 3, and notary serve refuses to start on it", async () => {
  const env = await setup({ s_aaaa0001: 2, s_bbbb0002: 2 });
  try {
    for (const session of ["s_aaaa0001", "s_bbbb0002"]) await countersignSession({ url: env.notary.url, session, keyId: env.opKey, notaryKeyId: env.noKey, home: env.op });
    await env.notary.close();
    const log = notaryPaths(env.no).log;
    const original = readFileSync(log, "utf8");
    // One edited byte in the first receipt.
    writeFileSync(log, original.replace('"session":"s_aaaa0001"', '"session":"s_aaaa0009"'));
    const edited = await run(["notary", "verify"], { WITNESS_HOME: env.no });
    assert.equal(edited.code, 3, edited.out);
    assert.match(edited.out, /^FAIL .*log\.jsonl {2}0 receipts .*: hash mismatch at seq 0$/m);
    await assert.rejects(startNotaryServer({ home: env.no, keyId: env.noKey, port: 0 }), (error) => error.exitCode === 3 && /is broken: hash mismatch at seq 0\. Not serving\./.test(error.message));
    const serve = await run(["notary", "serve", "--key", env.noKey, "--port", "0"], { WITNESS_HOME: env.no });
    assert.equal(serve.code, 3, serve.err);
    assert.equal(serve.out, "");
    // A dropped receipt breaks prev; a stripped signer fails because the hash does not cover it.
    const lines = original.split("\n").filter(Boolean);
    writeFileSync(log, `${lines[1]}\n`);
    assert.match(verifyNotaryLog({ home: env.no }).reason, /prev mismatch at seq 1/);
    const { signer: _s, ...stripped } = JSON.parse(lines[0]);
    writeFileSync(log, `${JSON.stringify(stripped)}\n${lines[1]}\n`);
    assert.match(verifyNotaryLog({ home: env.no }).reason, /missing signer at seq 0/);
    // A blank line is a broken log too, and the intact log verifies again.
    writeFileSync(log, `${lines[0]}\n\n${lines[1]}\n`);
    const blank = await run(["notary", "verify"], { WITNESS_HOME: env.no });
    assert.equal(blank.code, 3, blank.out);
    assert.match(blank.out, /log\.jsonl line 2 is blank/);
    writeFileSync(log, original);
    assert.equal((await run(["notary", "verify", "--key", env.noKey], { WITNESS_HOME: env.no })).code, 0);
    assert.equal((await run(["notary", "verify", "--key", env.opKey], { WITNESS_HOME: env.no })).code, 3);
  } finally {
    await env.cleanup();
  }
});

test("notary serve: caps the body at 413, answers 405, 404 and 400, and caps concurrent requests at 503", async () => {
  const home = await tempHome();
  const { keyId } = keygen(home);
  const notary = await startNotaryServer({ home, keyId, port: 0, limits: { maxBody: 1024, maxConcurrent: 2, stallMs: 2000, rate: 10_000 } });
  try {
    // A declared length over the cap is refused before the body is read.
    const declared = await rawRequest(notary.port, `POST /receipt HTTP/1.1\r\nHost: n\r\nContent-Type: application/json\r\nContent-Length: 4096\r\n\r\n${"x".repeat(100)}`);
    assert.match(declared, /^HTTP\/1\.1 413 /);
    // A chunked body with no length is cut off when it passes the cap.
    const chunk = "y".repeat(800);
    const chunked = await rawRequest(notary.port, `POST /receipt HTTP/1.1\r\nHost: n\r\nTransfer-Encoding: chunked\r\n\r\n${chunk.length.toString(16)}\r\n${chunk}\r\n${chunk.length.toString(16)}\r\n${chunk}\r\n`);
    assert.match(chunked, /^HTTP\/1\.1 413 /);
    assert.equal(existsSync(notaryPaths(home).log), false, "nothing was appended");
    for (const method of ["GET", "PUT", "DELETE"]) {
      const res = await fetch(notary.url, { method });
      assert.equal(res.status, 405, method);
      assert.equal(res.headers.get("allow"), "POST");
    }
    const base = notary.url.slice(0, -"/receipt".length);
    for (const p of ["/", "/receipts", "/feed", `/keys/${keyId}.key`, "/notary/log.jsonl"]) assert.equal((await post(`${base}${p}`, "{}")).status, 404, p);
    assert.equal((await post(notary.url, "not json")).status, 400);
    assert.equal((await post(notary.url, Buffer.from([0x7b, 0xff, 0x7d]))).status, 400, "invalid UTF-8");
    const malformed = await post(notary.url, { v: "0.4", type: "head" });
    assert.equal(malformed.status, 400);
    assert.match(malformed.text, /expected \["alg","hash"/);
    // Two clients send headers and hold their bodies: a third request gets 503.
    const held = [0, 1].map(() => { const s = net.connect(notary.port, "127.0.0.1"); s.on("error", () => {}); s.write("POST /receipt HTTP/1.1\r\nHost: n\r\nContent-Length: 500\r\n\r\n{"); return s; });
    await new Promise((resolve) => setTimeout(resolve, 200));
    const busy = await post(notary.url, "{}");
    assert.equal(busy.status, 503);
    assert.equal(busy.headers.get("retry-after"), "1");
    for (const s of held) s.destroy();
    await new Promise((resolve) => setTimeout(resolve, 200));
    assert.equal((await post(notary.url, "{}")).status, 400, "the slots are free again");
  } finally {
    await notary.close();
  }
  await rm(home, { recursive: true, force: true });
});

test("notary serve: refuses an empty host and every-interface hosts unless --any-interface is given", async () => {
  const home = await tempHome();
  const { keyId } = keygen(home);
  const env = { WITNESS_HOME: home };
  for (const [host, reason] of [["", /--host must be a host name or an address, not ""/], ["0.0.0.0", /means every interface \(0\.0\.0\.0\)\. Pass --any-interface/], ["::", /means every interface \(::\)/], ["::ffff:0.0.0.0", /means every interface/]]) {
    const result = await run(["notary", "serve", "--key", keyId, "--host", host, "--port", "0"], env);
    assert.equal(result.code, 1, `${JSON.stringify(host)}: ${result.out}${result.err}`);
    assert.match(result.err, reason, JSON.stringify(host));
    assert.equal(result.out, "", "nothing listens");
  }
  await assert.rejects(startNotaryServer({ home, keyId, host: "0.0.0.0", port: 0 }), /Pass --any-interface/);
  const any = await startNotaryServer({ home, keyId, host: "0.0.0.0", port: 0, anyInterface: true });
  try { assert.equal(any.host, "0.0.0.0"); } finally { await any.close(); }
  const plain = await startNotaryServer({ home, keyId, port: 0 });
  try { assert.equal(plain.host, "127.0.0.1"); } finally { await plain.close(); }
  // A missing key, or a .key without its .pub, is exit 1.
  assert.equal((await run(["notary", "serve", "--key", "k_00000000", "--port", "0"], env)).code, 1);
  await rm(home, { recursive: true, force: true });
});

test("review 3: a head or receipt signature in any spelling but canonical base64 of 64 bytes is refused", async () => {
  const env = await setup();
  try {
    const { head } = sealSession({ session: "s_aaaa0001", keyId: env.opKey, home: env.op });
    const last = head.sig.charCodeAt(head.sig.length - 3);
    // The same 64 bytes spelled four other ways, and 65 bytes.
    const spellings = [head.sig.replace(/==$/, ""), `${head.sig.slice(0, -3)}${String.fromCharCode(last ^ 1)}==`, `${head.sig}\n`, ` ${head.sig}`, Buffer.alloc(65, 1).toString("base64")];
    for (const sig of spellings) {
      const variant = { ...head, sig };
      assert.notEqual(headDigest(variant), headDigest(head));
      assert.deepEqual(checkHead(variant), { kind: "malformed", reason: "the head sig is not canonical base64 of 64 bytes" }, JSON.stringify(sig));
      assert.equal((await post(env.notary.url, variant)).status, 400, JSON.stringify(sig));
    }
    assert.equal(existsSync(notaryPaths(env.no).log), false, "no receipt for any spelling");
    const { receipt } = await countersignSession({ url: env.notary.url, session: "s_aaaa0001", keyId: env.opKey, notaryKeyId: env.noKey, home: env.op });
    assert.equal(checkReceipt(receipt, { notaryKeyId: env.noKey, home: env.op }), null);
    for (const sig of [receipt.signer.sig.replace(/==$/, ""), `${receipt.signer.sig}\n`, ` ${receipt.signer.sig}`]) {
      const variant = { ...receipt, signer: { ...receipt.signer, sig } };
      assert.equal(receiptShape(variant), "the receipt signer.sig is not canonical base64 of 64 bytes");
      assert.equal(checkReceipt(variant, { notaryKeyId: env.noKey, home: env.op }).kind, "malformed");
    }
  } finally {
    await env.cleanup();
  }
});

test("review 8: seq and record counts must be safe integers, and ts a strict ISO-8601 UTC timestamp", async () => {
  const env = await setup();
  try {
    const { head } = sealSession({ session: "s_aaaa0001", keyId: env.opKey, home: env.op });
    const key = loadKey(env.opKey, env.op);
    const { sig: _sig, ...body } = head;
    const bad = [
      [{ seq: 2 ** 60, records: 2 ** 60 + 1 }, /seq is not a safe integer/],
      [{ seq: Number.MAX_SAFE_INTEGER, records: Number.MAX_SAFE_INTEGER + 1 }, /seq is not a safe integer/],
      [{ ts: "1" }, /ts is not an ISO-8601 UTC timestamp/],
      [{ ts: "2026-10-23T02:00:00Z" }, /ts is not an ISO-8601 UTC timestamp/],
      [{ ts: "2026-02-30T00:00:00.000Z" }, /ts is not an ISO-8601 UTC timestamp/],
      [{ ts: "2026-10-23T02:00:00.000+00:00" }, /ts is not an ISO-8601 UTC timestamp/],
    ];
    for (const [change, reason] of bad) {
      const signed = signHead({ ...body, ...change }, key);
      assert.match(checkHead(signed).reason, reason, JSON.stringify(change));
      assert.equal((await post(env.notary.url, signed)).status, 400, JSON.stringify(change));
    }
    assert.equal(checkHead(head), null);
    const { receipt } = await countersignSession({ url: env.notary.url, session: "s_aaaa0001", keyId: env.opKey, notaryKeyId: env.noKey, home: env.op });
    assert.match(receiptShape({ ...receipt, seq: 2 ** 60 }), /seq is not a safe integer/);
    assert.match(receiptShape({ ...receipt, ts: "yesterday" }), /ts is not an ISO-8601 UTC timestamp/);
    assert.match(receiptShape({ ...receipt, head: { ...receipt.head, seq: 2 ** 60 } }), /bad sha256, hash, seq/);
  } finally {
    await env.cleanup();
  }
});

test("review 6: the exit code follows the order of SPEC-0.4 section 4, not the order of lines in the files", async () => {
  const env = await setup({ s_aaaa0001: 2, s_bbbb0002: 2 });
  try {
    for (const session of ["s_aaaa0001", "s_bbbb0002"]) await countersignSession({ url: env.notary.url, session, keyId: env.opKey, notaryKeyId: env.noKey, home: env.op });
    const home = await outsider(env, "s_aaaa0001");
    const key = loadKey(env.opKey, env.op);
    const [head] = readJson(headsFile("s_aaaa0001", home));
    const { sig: _sig, ...body } = head;
    // Line 1: signed, but the wrong hash (exit 3). Line 2: a bad signature (exit 4). Section 4 checks signatures first.
    const wrongHash = signHead({ ...body, hash: "f".repeat(64) }, key);
    const badSig = { ...signHead({ ...body, hash: "e".repeat(64) }, key), seq: 0, records: 1 };
    writeJson(headsFile("s_aaaa0001", home), [wrongHash, badSig]);
    const heads = checkSession({ session: "s_aaaa0001", notaryKeyId: env.noKey, home });
    assert.deepEqual(heads.failures.slice(0, 2).map((f) => f.code), [CHECK_EXIT.headSignature, CHECK_EXIT.head]);
    assert.equal(heads.code, CHECK_EXIT.headSignature);
    // Receipts: line 1 names another session's head (exit 6), line 2 has a bad signature (exit 5). Exit 5 comes first.
    writeJson(headsFile("s_aaaa0001", home), [head]);
    const [other] = readJson(receiptsFile("s_bbbb0002", env.op));
    const [own] = readJson(receiptsFile("s_aaaa0001", env.op));
    const flipped = Buffer.from(own.signer.sig, "base64"); flipped[0] ^= 1;
    writeJson(receiptsFile("s_aaaa0001", home), [other, { ...own, signer: { ...own.signer, sig: flipped.toString("base64") } }]);
    const receipts = checkSession({ session: "s_aaaa0001", notaryKeyId: env.noKey, home });
    assert.deepEqual(receipts.failures.map((f) => f.code), [CHECK_EXIT.receiptSignature, CHECK_EXIT.receiptHead]);
    assert.equal(receipts.code, CHECK_EXIT.receiptSignature);
    await rm(home, { recursive: true, force: true });
  } finally {
    await env.cleanup();
  }
});

test("review 9: a blank, garbage or non-UTF-8 line in the session log is a broken chain, exit 2", async () => {
  const env = await setup();
  try {
    await countersignSession({ url: env.notary.url, session: "s_aaaa0001", keyId: env.opKey, notaryKeyId: env.noKey, home: env.op });
    const home = await outsider(env, "s_aaaa0001");
    const log = path.join(logDir(home), "s_aaaa0001.jsonl");
    const original = readFileSync(log);
    for (const [name, bytes] of [["blank", Buffer.concat([original, Buffer.from("\n")])], ["garbage", Buffer.concat([original, Buffer.from("not json\n")])], ["utf8", Buffer.concat([original, Buffer.from([0xff, 0x0a])])]]) {
      writeFileSync(log, bytes);
      const result = await run(["check", "s_aaaa0001", "--notary", env.noKey], { WITNESS_HOME: home });
      assert.equal(result.code, 2, `${name}: ${result.out}`);
      assert.match(result.out, /^FAIL chain s_aaaa0001: /m, name);
    }
    // A missing log is still exit 1.
    await rm(log, { force: true });
    assert.equal(checkSession({ session: "s_aaaa0001", notaryKeyId: env.noKey, home }).code, CHECK_EXIT.error);
    await rm(home, { recursive: true, force: true });
  } finally {
    await env.cleanup();
  }
});

test("review 2: countersign says SAME only for a stored receipt that passes the checks with the requested notary key", async () => {
  const env = await setup();
  const other = await tempHome();
  const otherKey = keygen(other).keyId;
  const second = await startNotaryServer({ home: other, keyId: otherKey, port: 0, limits: { rate: 10_000 } });
  try {
    // A receipt from the first notary, stored unverified: this home has no .pub for it.
    await rm(path.join(env.op, "keys", `${env.noKey}.pub`));
    const first = await countersignSession({ url: env.notary.url, session: "s_aaaa0001", keyId: env.opKey, home: env.op });
    assert.equal(first.verified, false);
    // Asked for the second notary by key: the stored receipt is signed by another key, so the head is sent.
    trust(other, env.op, otherKey);
    const asked = await countersignSession({ url: second.url, session: "s_aaaa0001", keyId: env.opKey, notaryKeyId: otherKey, home: env.op });
    assert.equal(asked.sent, true);
    assert.equal(asked.receipt.signer.key_id, otherKey);
    assert.equal((await countersignSession({ url: second.url, session: "s_aaaa0001", keyId: env.opKey, notaryKeyId: otherKey, home: env.op })).sent, false);
    // A stored receipt whose signature was replaced does not count: the head is sent again.
    const file = receiptsFile("s_aaaa0001", env.op);
    const stored = readJson(file);
    writeJson(file, stored.map((r) => (r.signer.key_id === otherKey ? { ...r, signer: { ...r.signer, sig: Buffer.alloc(64).toString("base64") } } : r)));
    const again = await countersignSession({ url: second.url, session: "s_aaaa0001", keyId: env.opKey, notaryKeyId: otherKey, home: env.op });
    assert.equal(again.sent, true);
    assert.equal(again.verified, true);
    const then = await countersignSession({ url: second.url, session: "s_aaaa0001", keyId: env.opKey, notaryKeyId: otherKey, home: env.op });
    assert.equal(then.sent, false);
    assert.equal(then.verified, true);
    assert.equal(readLines(notaryPaths(other).log).length, 2);
  } finally {
    await second.close();
    await rm(other, { recursive: true, force: true });
    await env.cleanup();
  }
});

async function withFs(wrappers, fn) {
  const saved = {};
  for (const [name, wrap] of Object.entries(wrappers)) { saved[name] = fs[name]; fs[name] = wrap(saved[name]); }
  syncBuiltinESMExports();
  try { return await fn(); } finally { Object.assign(fs, saved); syncBuiltinESMExports(); }
}

test("review 4: the notary fsyncs its log before it answers 200, and seal and countersign fsync heads and receipts", async () => {
  const env = await setup();
  try {
    const names = new Map();
    const calls = [];
    const watch = {
      openSync: (real) => (file, ...rest) => { const fd = real(file, ...rest); names.set(fd, String(file)); return fd; },
      fsyncSync: (real) => (fd) => { const name = names.get(fd) ?? ""; calls.push(`fsync ${path.basename(path.dirname(name))}/${path.basename(name)}`); return real(fd); },
    };
    await withFs(watch, async () => {
      const original = globalThis.fetch;
      const fetchImpl = async (...args) => { const res = await original(...args); calls.push("reply"); return res; };
      const result = await countersignSession({ url: env.notary.url, session: "s_aaaa0001", keyId: env.opKey, notaryKeyId: env.noKey, home: env.op, fetchImpl });
      assert.equal(result.sent, true);
    });
    const tag = (dir, name) => `fsync ${path.basename(dir)}/${name}`;
    const order = calls.filter((c) => c === "reply" || c.includes("heads") || c.includes("notary") || c.includes("receipts"));
    assert.deepEqual(order, [
      tag(path.join(env.op, "heads"), "s_aaaa0001.jsonl"), tag(env.op, "heads"),
      tag(path.join(env.no, "notary"), "log.jsonl"), tag(env.no, "notary"),
      "reply",
      tag(path.join(env.op, "receipts"), "s_aaaa0001.jsonl"), tag(env.op, "receipts"),
    ]);
    assert.equal(statSync(notaryPaths(env.no).log).mode & 0o777, 0o600);
    assert.equal(statSync(receiptsFile("s_aaaa0001", env.op)).mode & 0o777, 0o600);
    assert.equal(statSync(headsFile("s_aaaa0001", env.op)).mode & 0o777, 0o600);
  } finally {
    await env.cleanup();
  }
});

test("review 5: notary serve caps requests per second for all clients with 429, and checks its tail by reading one line", async () => {
  const env = await setup();
  const { head } = sealSession({ session: "s_aaaa0001", keyId: env.opKey, home: env.op });
  await env.notary.close();
  const notary = await startNotaryServer({ home: env.no, keyId: env.noKey, port: 0, limits: { rate: 3 } });
  try {
    const replies = await Promise.all(Array.from({ length: 8 }, () => post(notary.url, head)));
    assert.equal(replies.filter((r) => r.status === 200).length, 3, replies.map((r) => r.status).join(","));
    const limited = replies.filter((r) => r.status === 429);
    assert.equal(limited.length, 5);
    for (const r of limited) assert.equal(r.headers.get("retry-after"), "1");
    assert.equal(readLines(notaryPaths(env.no).log).length, 3);
    await new Promise((resolve) => setTimeout(resolve, 1100));
    assert.equal((await post(notary.url, head)).status, 200, "the bucket refills");
    // Each append reads only the last line and the newline before it, not the log.
    const log = notaryPaths(env.no).log;
    const names = new Map();
    let bytes = 0;
    await new Promise((resolve) => setTimeout(resolve, 400));
    await withFs({
      openSync: (real) => (file, ...rest) => { const fd = real(file, ...rest); names.set(fd, String(file)); return fd; },
      readSync: (real) => (fd, buffer, ...rest) => { const n = real(fd, buffer, ...rest); if (names.get(fd) === log) bytes += n; return n; },
      readFileSync: (real) => (file, ...rest) => { const out = real(file, ...rest); if (String(file) === log) bytes += out.length; return out; },
    }, async () => assert.equal((await post(notary.url, head)).status, 200));
    const lines = readLines(log);
    assert.equal(lines.length, 5);
    assert.equal(bytes, Buffer.byteLength(lines[3]) + 2, `read ${bytes} bytes of a ${statSync(log).size}-byte log`);
    // Another writer changes the log: the tail no longer matches, the whole log is verified, and serving stops.
    writeFileSync(log, `${lines.slice(0, 4).join("\n")}\n{"tampered":true}\n`);
    await new Promise((resolve) => setTimeout(resolve, 400));
    assert.equal((await post(notary.url, head)).status, 500);
    await new Promise((resolve) => setTimeout(resolve, 400));
    assert.equal((await post(notary.url, head)).status, 500);
  } finally {
    await notary.close();
    await env.cleanup();
  }
  // The CLI flag, and a bad value.
  const home = await tempHome();
  const { keyId } = keygen(home);
  const bad = await run(["notary", "serve", "--key", keyId, "--port", "0", "--rate", "0"], { WITNESS_HOME: home });
  assert.equal(bad.code, 1);
  assert.match(bad.err, /--rate must be a number of requests per second above 0/);
  await rm(home, { recursive: true, force: true });
});

test("review 7: --notary and --operator take the full 64-hex fingerprint; a key_id alone is accepted with a NOTE", async () => {
  const env = await setup();
  try {
    const noFp = fingerprintOf(readFileSync(path.join(env.no, "keys", `${env.noKey}.pub`), "utf8"));
    const opFp = fingerprintOf(readFileSync(path.join(env.op, "keys", `${env.opKey}.pub`), "utf8"));
    assert.equal(env.notary.fingerprint, noFp);
    assert.equal(noFp.slice(0, 8), env.noKey.slice(2));
    // countersign pins the notary by fingerprint; a key_id alone warns on stderr.
    const pinned = await run(["countersign", env.notary.url, "s_aaaa0001", "--key", env.opKey, "--notary", noFp], { WITNESS_HOME: env.op });
    assert.equal(pinned.code, 0, pinned.out + pinned.err);
    assert.doesNotMatch(pinned.err, /32-bit/);
    const short = await run(["countersign", env.notary.url, "s_aaaa0001", "--key", env.opKey, "--notary", env.noKey], { WITNESS_HOME: env.op });
    assert.equal(short.code, 0);
    assert.match(short.err, new RegExp(`--notary ${env.noKey} is a 32-bit key_id\\. Pin the key: --notary ${noFp}`));
    const home = await outsider(env, "s_aaaa0001", { operatorPub: true });
    const full = await run(["check", "s_aaaa0001", "--notary", noFp, "--operator", opFp], { WITNESS_HOME: home });
    assert.equal(full.code, 0, full.out);
    assert.match(full.out, new RegExp(`^OK   notary key ${env.noKey} fingerprint ${noFp}$`, "m"));
    assert.match(full.out, new RegExp(`^OK   operator key ${env.opKey} fingerprint ${opFp}$`, "m"));
    assert.doesNotMatch(full.out, /^NOTE/m);
    const byId = checkSession({ session: "s_aaaa0001", notaryKeyId: env.noKey, operatorKeyId: env.opKey, home });
    assert.equal(byId.code, 0);
    assert.ok(byId.notes.includes(`--notary ${env.noKey} is a 32-bit key_id, and any key with that prefix is accepted. Pin the key: --notary ${noFp}`));
    assert.ok(byId.notes.includes(`--operator ${env.opKey} is a 32-bit key_id, and any key with that prefix is accepted. Pin the key: --operator ${opFp}`));
    // A fingerprint that shares the 8-hex prefix but not the rest: the .pub found by key_id is not that key.
    const twin = `${noFp.slice(0, 8)}${noFp.slice(8).split("").reverse().join("")}`;
    assert.notEqual(twin, noFp);
    assert.match(pinnedKey(twin, home).problem, new RegExp(`keys/${env.noKey}\\.pub has fingerprint ${noFp}, not ${twin}`));
    const wrongNotary = await run(["check", "s_aaaa0001", "--notary", twin], { WITNESS_HOME: home });
    assert.equal(wrongNotary.code, 5, wrongNotary.out);
    const opTwin = `${opFp.slice(0, 8)}${"0".repeat(56)}`;
    const wrongOperator = checkSession({ session: "s_aaaa0001", notaryKeyId: noFp, operatorKeyId: opTwin, home });
    assert.equal(wrongOperator.code, CHECK_EXIT.headSignature);
    assert.match(wrongOperator.failures[0].message, /has fingerprint [0-9a-f]{64}, not 0*/);
    assert.equal(checkSession({ session: "s_aaaa0001", notaryKeyId: "abc", home }).code, CHECK_EXIT.error);
    // keygen prints the fingerprint for peers to pin.
    const made = await run(["keygen"], { WITNESS_HOME: home });
    const madeId = made.out.trim();
    assert.match(made.err, new RegExp(`fingerprint ${madeId.slice(2)}[0-9a-f]{56}\\. Peers pin the key with it\\.`));
    await rm(home, { recursive: true, force: true });
  } finally {
    await env.cleanup();
  }
});

test("review 1: a log rewritten and countersigned again passes on the operator's files alone, and exits 8 against the notary log", async () => {
  const env = await setup({ s_aaaa0001: 3, s_bbbb0002: 2 });
  try {
    for (const session of ["s_bbbb0002", "s_aaaa0001"]) await countersignSession({ url: env.notary.url, session, keyId: env.opKey, notaryKeyId: env.noKey, home: env.op });
    // The operator rewrites the log, removes heads and receipts, and countersigns the rewrite.
    const log = path.join(logDir(env.op), "s_aaaa0001.jsonl");
    await rm(log);
    writeSession(env.op, "s_aaaa0001", 3, 100);
    await rm(headsFile("s_aaaa0001", env.op));
    await rm(receiptsFile("s_aaaa0001", env.op));
    await countersignSession({ url: env.notary.url, session: "s_aaaa0001", keyId: env.opKey, notaryKeyId: env.noKey, home: env.op });
    const home = await outsider(env, "s_aaaa0001");
    const alone = await run(["check", "s_aaaa0001", "--notary", env.noKey], { WITNESS_HOME: home });
    assert.equal(alone.code, 0, "the operator's files alone cannot show the rewrite");
    assert.match(alone.out, /\(notary seq 2\)$/m);
    // The checker gets the notary log from the notary.
    const copy = path.join(home, "notary-log.jsonl");
    copyFileSync(notaryPaths(env.no).log, copy);
    const against = await run(["check", "s_aaaa0001", "--notary", env.noKey, "--notary-log", copy], { WITNESS_HOME: home });
    assert.equal(against.code, 8, against.out);
    assert.match(against.out, /^FAIL notary log seq 1 receipted head [0-9a-f]{12} \(seq 2, hash [0-9a-f]{12}\) at .*, which is not in heads\/s_aaaa0001\.jsonl$/m);
    assert.doesNotMatch(against.out, /notary log seq 0/, "another session's receipts are not this session's");
    // An honest session passes against the same log.
    const honest = await outsider(env, "s_bbbb0002");
    const ok = checkSession({ session: "s_bbbb0002", notaryKeyId: env.noKey, notaryLog: copy, home: honest });
    assert.equal(ok.code, 0, JSON.stringify(ok.failures));
    assert.ok(ok.passed.includes("notary log: 3 receipts, 1 for s_bbbb0002, every one names a presented head"));
    // A presented receipt that the notary log does not hold, a log that does not verify, and a missing file.
    writeFileSync(copy, readLines(notaryPaths(env.no).log).slice(0, 2).map((l) => `${l}\n`).join(""));
    const short = checkSession({ session: "s_aaaa0001", notaryKeyId: env.noKey, notaryLog: copy, home });
    assert.equal(short.code, CHECK_EXIT.notaryLog);
    assert.ok(short.failures.some((f) => f.message === "receipt 1 of receipts/s_aaaa0001.jsonl is not in the notary log at seq 2"));
    writeFileSync(copy, readFileSync(notaryPaths(env.no).log, "utf8").replace('"session":"s_bbbb0002"', '"session":"s_bbbb0003"'));
    const broken = checkSession({ session: "s_aaaa0001", notaryKeyId: env.noKey, notaryLog: copy, home });
    assert.equal(broken.code, CHECK_EXIT.notaryLog);
    assert.match(broken.failures[0].message, /does not verify under k_[0-9a-f]{8}: hash mismatch at seq 0/);
    assert.equal(checkSession({ session: "s_aaaa0001", notaryKeyId: env.noKey, notaryLog: path.join(home, "nope.jsonl"), home }).code, CHECK_EXIT.error);
    for (const dir of [home, honest]) await rm(dir, { recursive: true, force: true });
  } finally {
    await env.cleanup();
  }
});
