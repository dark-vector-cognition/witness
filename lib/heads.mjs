// witness seal: signed chain heads. Format v0.4, see SPEC-0.4.md section 2.
// A head statement names the last record of one session chain and is signed by the operator key.
// seal reads log/<session>.jsonl and appends to heads/<session>.jsonl. It never opens a session file for writing.
import { createPrivateKey, createPublicKey, sign as edSign, verify as edVerify } from "node:crypto";
import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { readFeedFile } from "./feed.mjs";
import { withChainLock } from "./judge.mjs";
import { KEY_ID_PATTERN, keyIdOf, keysDir } from "./keys.mjs";
import { canonical, sha256, verifyChain } from "./record.mjs";
import { listSessionFiles, logDir, witnessHome } from "./session-log.mjs";

export const HEAD_VERSION = "0.4";
/** Exit codes for seal and countersign. */
export const EXIT = { ok: 0, error: 1, broken: 3 };

const SESSION_PATTERN = /^[A-Za-z0-9_.-]{1,128}$/;
const HASH_PATTERN = /^[0-9a-f]{64}$/;
const TS_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const HEAD_FIELDS = ["alg", "hash", "key_id", "public_key", "records", "seq", "session", "sig", "ts", "type", "v"];

/** An error that carries the CLI exit code. */
export class HeadError extends Error {
  constructor(message, exitCode = EXIT.error) {
    super(message);
    this.exitCode = exitCode;
  }
}

export function headsDir(home = witnessHome()) {
  return path.join(home, "heads");
}

export function headsFile(session, home = witnessHome()) {
  return path.join(headsDir(home), `${session}.jsonl`);
}

export function validSession(session) {
  return typeof session === "string" && SESSION_PATTERN.test(session) && session !== "." && session !== "..";
}

/** True for an ISO-8601 UTC timestamp with millisecond precision that names a real instant, as toISOString writes it. */
export function validTimestamp(ts) {
  return typeof ts === "string" && TS_PATTERN.test(ts) && !Number.isNaN(Date.parse(ts)) && new Date(ts).toISOString() === ts;
}

/** True for a safe integer >= 0. */
export function validCount(n) {
  return Number.isSafeInteger(n) && n >= 0;
}

/**
 * Decode an ed25519 signature: canonical base64 (padding included, no whitespace, unused bits zero) of exactly 64 bytes.
 * Returns the bytes, or null. Any other spelling of the same bytes is refused, so one signature has one text and one digest.
 */
export function signatureBytes(text) {
  if (typeof text !== "string") return null;
  const bytes = Buffer.from(text, "base64");
  return bytes.length === 64 && bytes.toString("base64") === text ? bytes : null;
}

/** sha256 of the canonical head statement, signature included. A receipt names its head by this digest. */
export function headDigest(head) {
  return sha256(canonical(head));
}

/** The public key in a head: base64 of the SPKI DER. */
export function publicKeyText(publicKey) {
  return publicKey.export({ type: "spki", format: "der" }).toString("base64");
}

/**
 * Load an ed25519 key pair from keys/<key_id>.key (the operator key for seal, the notary key for notary serve). The public key is derived from the private key, so no .pub is needed,
 * and the derived key must hash to key_id. Returns { keyId, privateKey, publicKey }. Throws HeadError exit 1.
 * The private key never leaves this function's return value and is never printed.
 */
export function loadKey(keyId, home = witnessHome()) {
  if (typeof keyId !== "string" || !KEY_ID_PATTERN.test(keyId)) throw new HeadError(`--key must be a key_id (k_ and 8 hex characters), not ${JSON.stringify(keyId ?? null)}`);
  const file = path.join(keysDir(home), `${keyId}.key`);
  let privateKey;
  try {
    privateKey = createPrivateKey(readFileSync(file, "utf8"));
  } catch (error) {
    throw new HeadError(error.code === "ENOENT" ? `no private key at ${file}` : `cannot load ${file}: ${error.code ?? "not a private key"}`);
  }
  if (privateKey.asymmetricKeyType !== "ed25519") throw new HeadError(`keys/${keyId}.key is not an ed25519 key`);
  const publicKey = createPublicKey(privateKey);
  const own = keyIdOf(publicKey);
  if (own !== keyId) throw new HeadError(`keys/${keyId}.key holds key ${own}, not ${keyId}`);
  return { keyId, privateKey, publicKey };
}

/** Sign a head body (every field but sig) with the operator key: ed25519 over the UTF-8 bytes of canonical(body). */
export function signHead(body, key) {
  return { ...body, sig: edSign(null, Buffer.from(canonical(body), "utf8"), key.privateKey).toString("base64") };
}

/**
 * Check one head statement on its own: shape, key_id against public_key, and the signature.
 * Returns null when it holds, or { kind, reason }. kind is "malformed", "key" (key_id does not match public_key)
 * or "signature". Never throws.
 */
export function checkHead(head) {
  try {
    if (!head || typeof head !== "object" || Array.isArray(head)) return { kind: "malformed", reason: "the head is not a JSON object" };
    const keys = Object.keys(head).sort();
    if (keys.join(",") !== HEAD_FIELDS.join(",")) return { kind: "malformed", reason: `the head has fields ${JSON.stringify(keys)}, expected ${JSON.stringify(HEAD_FIELDS)}` };
    if (head.v !== HEAD_VERSION) return { kind: "malformed", reason: `the head has v ${JSON.stringify(head.v)}, expected "${HEAD_VERSION}"` };
    if (head.type !== "head") return { kind: "malformed", reason: `the head has type ${JSON.stringify(head.type)}, expected "head"` };
    if (!validSession(head.session)) return { kind: "malformed", reason: "the head has an invalid session" };
    if (!validCount(head.seq) || !validCount(head.seq + 1)) return { kind: "malformed", reason: "the head seq is not a safe integer >= 0" };
    if (head.records !== head.seq + 1) return { kind: "malformed", reason: `the head says ${JSON.stringify(head.records)} records for seq ${head.seq}` };
    if (typeof head.hash !== "string" || !HASH_PATTERN.test(head.hash)) return { kind: "malformed", reason: "the head hash is not 64 lowercase hex characters" };
    if (!validTimestamp(head.ts)) return { kind: "malformed", reason: "the head ts is not an ISO-8601 UTC timestamp (YYYY-MM-DDTHH:MM:SS.sssZ)" };
    if (head.alg !== "ed25519") return { kind: "malformed", reason: `the head alg is ${JSON.stringify(head.alg)}, expected "ed25519"` };
    if (typeof head.key_id !== "string" || !KEY_ID_PATTERN.test(head.key_id)) return { kind: "malformed", reason: "the head key_id is not k_ and 8 hex characters" };
    if (typeof head.public_key !== "string" || typeof head.sig !== "string") return { kind: "malformed", reason: "the head public_key or sig is not a string" };
    const sigBytes = signatureBytes(head.sig);
    if (!sigBytes) return { kind: "malformed", reason: "the head sig is not canonical base64 of 64 bytes" };
    let publicKey;
    try {
      const der = Buffer.from(head.public_key, "base64");
      if (der.toString("base64") !== head.public_key) throw new Error("not canonical base64");
      publicKey = createPublicKey({ key: der, format: "der", type: "spki" });
    } catch {
      return { kind: "key", reason: "the head public_key is not a base64 SPKI public key" };
    }
    if (publicKey.asymmetricKeyType !== "ed25519") return { kind: "key", reason: "the head public_key is not an ed25519 key" };
    const actual = keyIdOf(publicKey);
    if (actual !== head.key_id) return { kind: "key", reason: `the head key_id ${head.key_id} does not match its public_key (${actual})` };
    const { sig: _sig, ...body } = head;
    const ok = edVerify(null, Buffer.from(canonical(body), "utf8"), publicKey, sigBytes);
    return ok ? null : { kind: "signature", reason: `the head signature does not verify against ${head.key_id}` };
  } catch (error) {
    return { kind: "malformed", reason: `the head cannot be checked (${error?.name}: ${error?.message})` };
  }
}

/**
 * Read a session chain for seal and check, with the strict parser: a blank or unparseable line is a problem.
 * Returns { records, problem }. problem is null for an intact chain whose every seq equals its position.
 * missing is true when the file does not exist.
 */
export function readSessionChain(session, home = witnessHome()) {
  const file = path.join(logDir(home), `${session}.jsonl`);
  if (!existsSync(file)) return { file, records: [], problem: `no session file at ${file}`, missing: true, parse: true };
  const parsed = readFeedFile(file);
  if (parsed.problem) return { file, records: [], problem: parsed.problem, missing: false, parse: true };
  const chain = verifyChain(parsed.records);
  if (!chain.ok) return { file, records: parsed.records, problem: chain.reason, missing: false, parse: false };
  const at = parsed.records.findIndex((r, i) => r.seq !== i);
  if (at !== -1) return { file, records: parsed.records, problem: `seq ${JSON.stringify(parsed.records[at].seq)} at position ${at}`, missing: false, parse: false };
  return { file, records: parsed.records, problem: null, missing: false, parse: false };
}

/** Read heads/<session>.jsonl with the strict parser. A missing file is no heads. Returns { file, heads, problem }. */
export function readHeads(session, home = witnessHome()) {
  const file = headsFile(session, home);
  const parsed = readFeedFile(file);
  return { file, heads: parsed.records, problem: parsed.problem };
}

/** Throw HeadError exit 3 when a non-empty file does not end with a newline: an append would join two lines. */
export function assertAppendable(file) {
  let text;
  try { text = readFileSync(file, "utf8"); } catch (error) { if (error.code === "ENOENT") return; throw new HeadError(`cannot read ${file}: ${error.code ?? error.message}`); }
  if (text !== "" && !text.endsWith("\n")) throw new HeadError(`${file} does not end with a newline. Nothing appended.`, EXIT.broken);
}

/**
 * witness seal <session> --key <key_id>. Verify the session chain, then append one signed head for its last record
 * to heads/<session>.jsonl, unless the last head there already names that seq and hash.
 * Returns { session, head, appended, file }. Throws HeadError: exit 3 for a broken chain or heads file, 1 otherwise.
 */
export function sealSession({ session, keyId, key = null, home = witnessHome(), now = () => new Date() }) {
  if (!validSession(session)) throw new HeadError(`invalid session id: ${JSON.stringify(session)}`);
  const operator = key ?? loadKey(keyId, home);
  const chain = readSessionChain(session, home);
  if (chain.missing) throw new HeadError(chain.problem);
  if (chain.problem) throw new HeadError(`${session} is broken: ${chain.problem}. Nothing sealed.`, EXIT.broken);
  if (chain.records.length === 0) throw new HeadError(`${session} has no records. Nothing sealed.`);
  const last = chain.records.at(-1);
  const file = headsFile(session, home);
  mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  return withChainLock(file, () => {
    const { heads, problem } = readHeads(session, home);
    if (problem) throw new HeadError(`${file} is broken: ${problem}. Nothing sealed.`, EXIT.broken);
    assertAppendable(file);
    const previous = heads.at(-1);
    if (previous) {
      const bad = checkHead(previous);
      if (bad) throw new HeadError(`${file} is broken: ${bad.reason}. Nothing sealed.`, EXIT.broken);
      if (previous.seq === last.seq && previous.hash === last.hash && previous.key_id === operator.keyId) return { session, head: previous, appended: false, file };
    }
    const head = signHead({ v: HEAD_VERSION, type: "head", session, seq: last.seq, hash: last.hash, records: chain.records.length, ts: now().toISOString(), key_id: operator.keyId, alg: "ed25519", public_key: publicKeyText(operator.publicKey) }, operator);
    appendFileSync(file, `${JSON.stringify(head)}\n`, { mode: 0o600 });
    return { session, head, appended: true, file };
  });
}

/** The session ids under log/, in the order listSessionFiles gives (oldest first). */
export function sessionIds(home = witnessHome()) {
  return listSessionFiles(logDir(home)).map((file) => path.basename(file, ".jsonl"));
}
