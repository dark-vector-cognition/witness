// witness notary and witness countersign. Format v0.4, see SPEC-0.4.md sections 3 and 5.
// A notary is a separate process, run by a party other than the operator, with its own key. It accepts a signed head
// statement, appends a signed receipt to its own hash-chained log, notary/log.jsonl, and returns the receipt.
// countersign seals each session if needed, sends the head, checks the receipt and appends it to receipts/<session>.jsonl.
import { sign as edSign } from "node:crypto";
import { closeSync, fstatSync, mkdirSync, openSync, readSync } from "node:fs";
import http from "node:http";
import path from "node:path";
import { appendDurable, readFeedFile, resolveServeHost, show } from "./feed.mjs";
import { EXIT, HeadError, assertAppendable, checkHead, headDigest, loadKey, sealSession, signatureBytes, validCount, validSession, validTimestamp } from "./heads.mjs";
import { withChainLock } from "./judge.mjs";
import { KEY_ID_PATTERN, trustedKey, trustedKeyLoader } from "./keys.mjs";
import { GENESIS, checkSigner, hashRecord, sealRecord, verifyChain } from "./record.mjs";
import { witnessHome } from "./session-log.mjs";

export const RECEIPT_VERSION = "0.4";
export const NOTARY_SESSION = "notary";
export const DEFAULT_NOTARY_PORT = 7481;
/** serve limits. maxBody caps a request body; a head statement is about 500 bytes. stallMs is the socket idle limit and the request limit. */
export const NOTARY_LIMITS = Object.freeze({ maxBody: 64 * 1024, maxConcurrent: 8, stallMs: 30_000 });
const MAX_REPLY_BYTES = 64 * 1024;
const REQUEST_TIMEOUT_MS = 30_000;
const TAIL_BYTES = 64 * 1024;
const HASH_PATTERN = /^[0-9a-f]{64}$/;
const RECEIPT_FIELDS = "event,hash,head,prev,seq,session,signer,ts,v";
const RECEIPT_HEAD_FIELDS = "hash,key_id,seq,session,sha256";
const SIGNER_FIELDS = "alg,key_id,sig";
const UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

export function notaryPaths(home = witnessHome()) {
  const dir = path.join(home, "notary");
  return { dir, log: path.join(dir, "log.jsonl") };
}

export function receiptsDir(home = witnessHome()) {
  return path.join(home, "receipts");
}

export function receiptsFile(session, home = witnessHome()) {
  return path.join(receiptsDir(home), `${session}.jsonl`);
}

/** Read receipts/<session>.jsonl with the strict parser. A missing file is no receipts. Returns { file, receipts, problem }. */
export function readReceipts(session, home = witnessHome()) {
  const file = receiptsFile(session, home);
  const parsed = readFeedFile(file);
  return { file, receipts: parsed.records, problem: parsed.problem };
}

function exactKeys(value, fields) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value) && Object.keys(value).sort().join(",") === fields;
}

/** The part of a receipt that names its head, built from the head statement. */
export function receiptHead(head) {
  return { sha256: headDigest(head), session: head.session, seq: head.seq, hash: head.hash, key_id: head.key_id };
}

/** null when the receipt has the exact fields of SPEC-0.4 section 3, or a reason. Never throws. */
export function receiptShape(receipt) {
  try {
    if (!exactKeys(receipt, RECEIPT_FIELDS)) return `the receipt does not have exactly the fields ${RECEIPT_FIELDS}`;
    if (receipt.v !== RECEIPT_VERSION || receipt.event !== "receipt" || receipt.session !== NOTARY_SESSION) return `the receipt is not a v ${RECEIPT_VERSION} "receipt" record of session "${NOTARY_SESSION}"`;
    if (!validCount(receipt.seq)) return "the receipt seq is not a safe integer >= 0";
    if (!validTimestamp(receipt.ts)) return "the receipt ts is not an ISO-8601 UTC timestamp (YYYY-MM-DDTHH:MM:SS.sssZ)";
    if (typeof receipt.prev !== "string" || typeof receipt.hash !== "string") return "the receipt prev or hash is not a string";
    const head = receipt.head;
    if (!exactKeys(head, RECEIPT_HEAD_FIELDS)) return `the receipt head does not have exactly the fields ${RECEIPT_HEAD_FIELDS}`;
    if (!HASH_PATTERN.test(String(head.sha256)) || !HASH_PATTERN.test(String(head.hash)) || !validCount(head.seq) || !validSession(head.session) || !KEY_ID_PATTERN.test(String(head.key_id))) return "the receipt head has a bad sha256, hash, seq, session or key_id";
    if (!exactKeys(receipt.signer, SIGNER_FIELDS) || receipt.signer.alg !== "ed25519" || !KEY_ID_PATTERN.test(String(receipt.signer.key_id)) || typeof receipt.signer.sig !== "string") return "the receipt signer is not { key_id, alg: \"ed25519\", sig }";
    if (!signatureBytes(receipt.signer.sig)) return "the receipt signer.sig is not canonical base64 of 64 bytes";
    return null;
  } catch (error) {
    return `the receipt cannot be checked (${error?.name}: ${error?.message})`;
  }
}

/**
 * Check a receipt's signature: shape, the hash recomputed with signer removed, and the ed25519 signature over the hash
 * against the trusted keys/<key_id>.pub. notaryKeyId, when set, must equal signer.key_id.
 * Returns null when it holds, or { kind, reason }: kind "malformed", "key" (wrong or untrusted notary key) or "signature".
 */
export function checkReceipt(receipt, { notaryKeyId = null, home = witnessHome() } = {}) {
  const shape = receiptShape(receipt);
  if (shape) return { kind: "malformed", reason: shape };
  try {
    const { signer, ...body } = receipt;
    if (notaryKeyId !== null && signer.key_id !== notaryKeyId) return { kind: "key", reason: `the receipt is signed by ${signer.key_id}, not ${notaryKeyId}` };
    const trust = trustedKey(signer.key_id, home);
    if (trust.problem) return { kind: "key", reason: `the notary key cannot be trusted: ${trust.problem}` };
    if (hashRecord(body, body.prev) !== body.hash) return { kind: "signature", reason: "the receipt hash does not match its content" };
    const bad = checkSigner(body.hash, signer, () => trust.pem);
    return bad ? { kind: "signature", reason: `the receipt has a ${bad}` } : null;
  } catch (error) {
    return { kind: "malformed", reason: `the receipt cannot be checked (${error?.name}: ${error?.message})` };
  }
}

/** null when the receipt names this head exactly (digest, session, seq, hash, key_id), or a reason. */
export function receiptMatches(receipt, head) {
  const want = receiptHead(head);
  for (const field of ["sha256", "session", "seq", "hash", "key_id"]) {
    if (receipt?.head?.[field] !== want[field]) return `the receipt head ${field} ${show(receipt?.head?.[field])} does not match the head (${show(want[field])})`;
  }
  return null;
}

/** An error that carries the CLI exit code. */
export class NotaryError extends Error {
  constructor(message, exitCode = EXIT.error) {
    super(message);
    this.exitCode = exitCode;
  }
}

/**
 * witness notary verify. Walk notary/log.jsonl: one chain, seq equal to the position, every record a receipt with the
 * fields of SPEC-0.4 section 3, every record signed by one trusted key (keyId when given). A missing log is an empty chain.
 * Returns { ok, count, keyId, reason, file }. A read error other than ENOENT gives readError true. Invalid UTF-8 or a blank or
 * unparseable line is a broken log, not a read error.
 */
export function verifyNotaryLog({ home = witnessHome(), keyId = null } = {}) {
  const file = notaryPaths(home).log;
  const parsed = readFeedFile(file);
  if (parsed.problem) return { ok: false, count: 0, keyId, reason: parsed.problem, file, readError: parsed.exitCode === EXIT.error };
  const records = parsed.records;
  try {
    const chain = verifyChain(records, { publicKeys: trustedKeyLoader(home), requireSigner: true });
    const end = chain.ok ? records.length : chain.brokenAt;
    const signerId = keyId ?? records[0]?.signer?.key_id ?? null;
    for (let i = 0; i < end; i += 1) {
      const fail = (reason) => ({ ok: false, count: i, keyId: signerId, reason, file });
      const shape = receiptShape(records[i]);
      if (shape) return fail(`${shape} at seq ${i}`);
      if (records[i].seq !== i) return fail(`seq ${show(records[i].seq)} at position ${i}`);
      if (records[i].signer.key_id !== signerId) return fail(`signer ${show(records[i].signer.key_id)} at seq ${i}, expected ${signerId}`);
    }
    return { ok: chain.ok, count: chain.ok ? records.length : chain.count, keyId: signerId, reason: chain.reason, file };
  } catch (error) {
    return { ok: false, count: 0, keyId, reason: `cannot be checked (${error?.name}: ${error?.message})`, file };
  }
}

/** The last line of a file, read from at most its last TAIL_BYTES. "" for a missing or empty file, null when it does not end with a newline or the line is longer. */
function lastLine(file) {
  let fd;
  try {
    fd = openSync(file, "r");
  } catch (error) {
    if (error.code === "ENOENT") return "";
    throw error;
  }
  try {
    const size = fstatSync(fd).size;
    if (size === 0) return "";
    const length = Math.min(size, TAIL_BYTES);
    const buffer = Buffer.alloc(length);
    readSync(fd, buffer, 0, length, size - length);
    if (buffer.at(-1) !== 0x0a) return null;
    const start = buffer.lastIndexOf(0x0a, length - 2);
    if (start === -1 && length < size) return null;
    return buffer.subarray(start + 1, length - 1).toString("utf8");
  } finally {
    closeSync(fd);
  }
}

function reply(res, status, body, headers = {}) {
  res.writeHead(status, { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff", ...headers, "content-length": Buffer.byteLength(body) });
  res.end(body);
}

/**
 * witness notary serve. An HTTP server bound only to `host`, after resolveServeHost checked it (the feed serve rules).
 * POST /receipt with one head statement as JSON. The notary checks the statement on its own (checkHead: shape, key_id
 * against the included public key, signature), appends one signed receipt to notary/log.jsonl and answers 200 with it.
 * 400: the body is not UTF-8 JSON or not a head statement. 413: the body is larger than limits.maxBody.
 * 422: key_id does not match public_key, or the signature does not verify. 405 with Allow: POST for another method.
 * 404 for every other path. 503 with Retry-After: 1 above limits.maxConcurrent requests. 500 when the log cannot be written
 * or no longer verifies; the server then refuses every later request. A 404, 405, 413 or 503 closes its connection.
 * The log is verified whole at start (a broken log: NotaryError exit 3). Before each append the last line on disk must be
 * the last line this server knows; otherwise the whole log is verified again.
 * Resolves to { server, host, port, url, keyId, file, close }.
 */
export async function startNotaryServer({ home = witnessHome(), keyId, host = "127.0.0.1", port = DEFAULT_NOTARY_PORT, anyInterface = false, limits = {}, onWarn = () => {}, now = () => new Date() } = {}) {
  const address = await resolveServeHost(host, { anyInterface });
  let key;
  try {
    key = loadKey(keyId, home);
  } catch (error) {
    throw new NotaryError(error.message);
  }
  const trust = trustedKey(keyId, home);
  if (trust.problem) throw new NotaryError(`${trust.problem}. The notary needs its own .pub to verify its log.`);
  const file = notaryPaths(home).log;
  mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const start = verifyNotaryLog({ home, keyId });
  if (!start.ok) throw new NotaryError(`${file} is broken: ${start.reason}. Not serving.`, start.readError ? EXIT.error : EXIT.broken);
  let known = lastLine(file);
  if (known === null) throw new NotaryError(`${file} does not end with a newline. Not serving.`, EXIT.broken);
  let broken = null;
  const max = { ...NOTARY_LIMITS, ...limits };

  const append = (head) => withChainLock(file, () => {
    if (broken) throw new Error(broken);
    const tail = lastLine(file);
    if (tail !== known) {
      const again = verifyNotaryLog({ home, keyId });
      const ending = lastLine(file);
      if (!again.ok || ending === null) {
        broken = `notary log broken: ${again.ok ? "no newline at the end" : again.reason}`;
        throw new Error(broken);
      }
      known = ending;
    }
    const last = known === "" ? null : JSON.parse(known);
    const sealed = sealRecord({ v: RECEIPT_VERSION, seq: last ? last.seq + 1 : 0, ts: now().toISOString(), session: NOTARY_SESSION, event: "receipt", head: receiptHead(head) }, last?.hash ?? GENESIS);
    const receipt = { ...sealed, signer: { key_id: key.keyId, alg: "ed25519", sig: edSign(null, Buffer.from(sealed.hash, "hex"), key.privateKey).toString("base64") } };
    const line = JSON.stringify(receipt);
    // On disk, with fsync of the file and notary/, before the 200 goes out.
    appendDurable(file, Buffer.from(`${line}\n`));
    known = line;
    return line;
  });

  let active = 0;
  const server = http.createServer({ requestTimeout: max.stallMs, headersTimeout: max.stallMs, connectionsCheckingInterval: Math.max(100, Math.floor(max.stallMs / 3)) }, (req, res) => {
    const target = req.url ?? "";
    const mark = target.indexOf("?");
    const pathname = mark === -1 ? target : target.slice(0, mark);
    // A request that is refused before its body is read closes the connection, so an unread body cannot follow it.
    const refuse = (status, body, headers = {}) => { reply(res, status, body, { connection: "close", ...headers }); res.once("finish", () => req.destroy()); };
    if (pathname !== "/receipt") return refuse(404, "not found\n");
    if (req.method !== "POST") return refuse(405, "method not allowed\n", { allow: "POST" });
    if (active >= max.maxConcurrent) return refuse(503, "busy\n", { "retry-after": "1" });
    const declared = Number(req.headers["content-length"]);
    if (Number.isFinite(declared) && declared > max.maxBody) return refuse(413, "body too large\n");
    active += 1;
    res.once("close", () => { active -= 1; });
    const chunks = [];
    let total = 0;
    let over = false;
    req.on("data", (chunk) => {
      if (over) return;
      total += chunk.length;
      if (total > max.maxBody) { over = true; chunks.length = 0; refuse(413, "body too large\n"); return; }
      chunks.push(chunk);
    });
    req.on("error", () => {});
    req.on("end", () => {
      if (over) return;
      let head;
      try { head = JSON.parse(UTF8.decode(Buffer.concat(chunks))); } catch { return reply(res, 400, "body is not UTF-8 JSON\n"); }
      const bad = checkHead(head);
      if (bad) return reply(res, bad.kind === "malformed" ? 400 : 422, `${bad.reason}\n`);
      let line;
      try {
        line = append(head);
      } catch (error) {
        onWarn(`receipt not written: ${error.code ?? error.message}`);
        return reply(res, 500, "notary log unavailable\n");
      }
      reply(res, 200, `${line}\n`, { "content-type": "application/json" });
    });
  });
  server.maxConnections = max.maxConcurrent * 4;
  server.setTimeout(max.stallMs, (socket) => socket.destroy());
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, address, () => {
      server.off("error", reject);
      const { address: boundAddress, port: bound } = server.address();
      const shown = boundAddress.includes(":") ? `[${boundAddress}]` : boundAddress;
      resolve({ server, host: boundAddress, port: bound, url: `http://${shown}:${bound}/receipt`, keyId: key.keyId, file, close: () => new Promise((done) => { server.close(() => done()); server.closeAllConnections(); }) });
    });
  });
}

/** The notary URL without userinfo and fragment. */
function notaryUrl(url) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    throw new NotaryError("invalid url");
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") throw new NotaryError("url must start with http:// or https://");
  parsed.username = "";
  parsed.password = "";
  parsed.hash = "";
  return parsed.toString();
}

/** One POST of the head to url. No redirect is followed. Returns the reply text. Network errors and a status other than 200 are NotaryError exit 1. */
async function postHead(url, head, fetchImpl) {
  let response;
  try {
    response = await fetchImpl(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(head), redirect: "error", signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
  } catch (error) {
    throw new NotaryError(`request to ${url} failed: ${error?.cause?.code ?? error?.cause?.message ?? error?.name ?? "error"}`);
  }
  const chunks = [];
  let total = 0;
  try {
    for await (const chunk of response.body ?? []) {
      total += chunk.length;
      if (total > MAX_REPLY_BYTES) throw new NotaryError(`reply from ${url} is larger than ${MAX_REPLY_BYTES} bytes`);
      chunks.push(chunk);
    }
  } catch (error) {
    if (error instanceof NotaryError) throw error;
    throw new NotaryError(`reading the reply from ${url} failed: ${error?.cause?.code ?? error?.name ?? "error"}`);
  }
  let text;
  try { text = UTF8.decode(Buffer.concat(chunks)); } catch { throw new NotaryError(`the reply from ${url} is not valid UTF-8`, EXIT.broken); }
  if (response.status !== 200) throw new NotaryError(`request to ${url} failed: HTTP ${response.status} ${show(text.split("\n")[0].slice(0, 200))}`);
  return text;
}

/**
 * The checks countersign applies to a receipt, new or stored: the fields of SPEC-0.4 section 3, the exact head, the hash
 * recomputed with signer removed, and the signature when notaryKeyId is given or keys/ trusts the signer.
 * Returns { problem, verified }. problem is null when the receipt passes. verified is true when its signature was checked.
 */
function receiptProblem(receipt, head, notaryKeyId, home) {
  const shape = receiptShape(receipt);
  if (shape) return { problem: shape, verified: false };
  const mismatch = receiptMatches(receipt, head);
  if (mismatch) return { problem: mismatch, verified: false };
  const { signer, ...body } = receipt;
  if (hashRecord(body, body.prev) !== body.hash) return { problem: "the receipt hash does not match its content", verified: false };
  if (notaryKeyId === null && trustedKey(signer.key_id, home).problem) return { problem: null, verified: false };
  const bad = checkReceipt(receipt, { notaryKeyId, home });
  return bad ? { problem: bad.reason, verified: false } : { problem: null, verified: true };
}

/**
 * witness countersign <url> for one session. Seal the session if its last head does not name the chain's last record,
 * send the head unless a stored receipt already names it and passes receiptProblem with notaryKeyId, check the receipt
 * and append it to receipts/<session>.jsonl.
 * The receipt must name this head (receiptMatches) and its hash must recompute. Its signature is checked when keys/ holds a
 * trusted .pub for its signer, and must be by notaryKeyId when that is given. A receipt that fails is not stored.
 * Returns { session, sent, receipt, verified, head }. Throws HeadError or NotaryError with an exit code.
 */
export async function countersignSession({ url, session, keyId, notaryKeyId = null, home = witnessHome(), fetchImpl = globalThis.fetch, now = () => new Date() }) {
  const target = notaryUrl(url);
  if (notaryKeyId !== null) {
    const trust = trustedKey(notaryKeyId, home);
    if (trust.problem) throw new NotaryError(`--notary ${notaryKeyId}: ${trust.problem}`);
  }
  const { head } = sealSession({ session, keyId, home, now });
  const file = receiptsFile(session, home);
  const existing = readReceipts(session, home);
  if (existing.problem) throw new NotaryError(`${file} is broken: ${existing.problem}. Nothing sent.`, EXIT.broken);
  assertAppendable(file);
  // SAME only for a stored receipt that names this head and passes every check a new receipt must pass, with the
  // requested notary key. A stored receipt that fails, or is signed by another notary, does not count: the head is sent.
  for (const stored of [...existing.receipts].reverse()) {
    if (receiptMatches(stored, head)) continue;
    const check = receiptProblem(stored, head, notaryKeyId, home);
    if (!check.problem) return { session, sent: false, receipt: stored, verified: check.verified, head };
  }
  const text = await postHead(target, head, fetchImpl);
  let receipt;
  try { receipt = JSON.parse(text); } catch { throw new NotaryError(`the reply from ${target} is not JSON. Nothing stored.`, EXIT.broken); }
  const { problem, verified } = receiptProblem(receipt, head, notaryKeyId, home);
  if (problem) throw new NotaryError(`${problem}. Nothing stored.`, EXIT.broken);
  mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  withChainLock(file, () => {
    assertAppendable(file);
    appendDurable(file, Buffer.from(`${JSON.stringify(receipt)}\n`));
  });
  return { session, sent: true, receipt, verified, head };
}

export { HeadError };
