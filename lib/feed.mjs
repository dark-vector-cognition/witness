// witness feed: a signed relay of refusal indicators between Witness homes. Format v0.2, see SPEC-0.2.md sections 2 and 5.
// The council mod writes feed/refusals.jsonl. This file only reads it.
// publish writes feed/published.jsonl. pull writes feed/remote/<key_id>.jsonl and feed/remote/peers.json. serve writes nothing.
import { createPrivateKey } from "node:crypto";
import { appendFileSync, constants, existsSync, mkdirSync, readFileSync, readdirSync, renameSync, writeFileSync } from "node:fs";
import { open } from "node:fs/promises";
import http from "node:http";
import path from "node:path";
import { pipeline } from "node:stream";
import { keySigner, withChainLock } from "./judge.mjs";
import { KEY_ID_PATTERN, keyIdOf, keysDir, trustedKey, trustedKeyLoader } from "./keys.mjs";
import { GENESIS, checkSigner, hashRecord, sealRecord, verifyChain } from "./record.mjs";
import { witnessHome } from "./session-log.mjs";

export const FEED_SCHEMA_VERSION = "0.2";
export const PUBLISHED_SESSION = "published";
export const DEFAULT_HOST = "127.0.0.1";
export const DEFAULT_PORT = 7480;
/** Exit codes for publish and pull. match uses 0 found, 1 not found, 2 error. */
export const EXIT = { ok: 0, error: 1, broken: 3 };

const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const AFTER_PATTERN = /^-?\d{1,15}$/;
const MAX_REPLY_BYTES = 32 * 1024 * 1024;
const PULL_TIMEOUT_MS = 30_000;
const NEWLINE = Buffer.from("\n");
/** serve limits. maxBytes matches the pull cap. stallMs is the socket idle limit and the request limit. */
export const SERVE_LIMITS = Object.freeze({ maxBytes: MAX_REPLY_BYTES, maxConcurrent: 8, stallMs: 30_000 });
const CHUNK_BYTES = 64 * 1024;
const MAX_SCAN_LINE = 1024 * 1024;

/** An error that carries the CLI exit code. pull also sets `appended`, the count of lines it kept. */
export class FeedError extends Error {
  constructor(message, exitCode = EXIT.error, details = {}) {
    super(message);
    this.exitCode = exitCode;
    Object.assign(this, details);
  }
}

export function feedPaths(home = witnessHome()) {
  const dir = path.join(home, "feed");
  const remote = path.join(dir, "remote");
  return { dir, local: path.join(dir, "refusals.jsonl"), published: path.join(dir, "published.jsonl"), remote, peers: path.join(remote, "peers.json") };
}

export function remoteFile(keyId, home = witnessHome()) {
  return path.join(feedPaths(home).remote, `${keyId}.jsonl`);
}

function validIndicator(indicator) {
  return Boolean(indicator) && typeof indicator.kind === "string" && indicator.kind !== "" && typeof indicator.sha256 === "string" && SHA256_PATTERN.test(indicator.sha256);
}

/**
 * Parse chain text into records. A line that is not a JSON object throws a FeedError with exit code 3.
 * A last line with no newline is parsed and checked like every other line.
 */
function parseChain(text, label) {
  const lines = text.split("\n");
  if (lines.at(-1) === "") lines.pop();
  const records = [];
  for (let i = 0; i < lines.length; i += 1) {
    if (lines[i].trim() === "") continue;
    let record;
    try { record = JSON.parse(lines[i]); } catch { record = null; }
    if (!record || typeof record !== "object" || Array.isArray(record)) throw new FeedError(`${label} line ${i + 1} is not a JSON object`, EXIT.broken);
    records.push(record);
  }
  return records;
}

/** Read and parse a chain file. Only ENOENT means a missing file, which is an empty chain. Any other read error is exit 1. */
function readChain(file, label) {
  let text;
  try {
    text = readFileSync(file, "utf8");
  } catch (error) {
    if (error.code === "ENOENT") return [];
    throw new FeedError(`cannot read ${file}: ${error.code ?? error.message}`);
  }
  return parseChain(text, label);
}

/**
 * The feed rules for a chain file, from its path and its records. null when the file is not a feed chain.
 * signed: every record needs a valid signer. keyId: every signer must be this key, because a remote copy holds one peer.
 */
export function feedChainRule(file, records = []) {
  const name = path.basename(file);
  const parent = path.basename(path.dirname(file));
  const grandparent = path.basename(path.dirname(path.dirname(file)));
  if (parent === "remote" && grandparent === "feed") return { signed: true, keyId: path.basename(file, ".jsonl") };
  if (name === "published.jsonl" || records.some((r) => r?.session === PUBLISHED_SESSION)) return { signed: true, keyId: null };
  if (name === "refusals.jsonl" && parent === "feed") return { signed: false, keyId: null };
  return null;
}

/**
 * Verify one feed file as one chain. On top of verifyChain: seq equals the position in the file,
 * a signed chain holds only `feed` records and every one has a signer, and a remote copy holds one key_id.
 * Signers are checked with trustedKeyLoader: a .pub counts only when it hashes to its key_id.
 * An exception during the walk (for example a record nested too deep to hash) is a broken chain, not a crash.
 */
export function verifyFeedChain(records, { signed = false, keyId = null, home = witnessHome() } = {}) {
  let chain;
  try {
    chain = verifyChain(records, { publicKeys: trustedKeyLoader(home), requireSigner: signed });
  } catch (error) {
    return { ok: false, count: 0, brokenAt: 0, reason: `cannot be checked (${error.name}: ${error.message})` };
  }
  const end = chain.ok ? records.length : chain.brokenAt;
  for (let i = 0; i < end; i += 1) {
    const record = records[i];
    const fail = (reason) => ({ ok: false, count: i, brokenAt: i, reason });
    if (record.seq !== i) return fail(`seq ${record.seq} at position ${i}`);
    if (signed && record.event !== "feed") return fail(`event ${record.event} at seq ${i}, expected feed`);
    if (keyId && record.signer?.key_id !== keyId) return fail(`signer ${record.signer?.key_id} at seq ${i} in the copy of ${keyId}`);
  }
  return chain;
}

/** keySigner for key_id, after a check that keys/<key_id>.key and keys/<key_id>.pub both belong to key_id. */
function signerFor(keyId, home) {
  if (!KEY_ID_PATTERN.test(keyId)) throw new FeedError(`invalid key_id ${JSON.stringify(keyId)}`);
  let sign;
  try {
    sign = keySigner(keyId, home);
  } catch (error) {
    throw new FeedError(error.message);
  }
  const own = keyIdOf(createPrivateKey(readFileSync(path.join(keysDir(home), `${keyId}.key`), "utf8")));
  if (own !== keyId) throw new FeedError(`keys/${keyId}.key holds key ${own}, not ${keyId}`);
  const { problem } = trustedKey(keyId, home);
  if (problem) throw new FeedError(`${problem}. publish needs the matching .pub to verify its own chain`);
  return sign;
}

/**
 * witness feed publish --key <key_id>.
 * Verify refusals.jsonl and published.jsonl. Then sign one record for every local feed record whose indicator.sha256
 * is not yet in published.jsonl. A second run appends nothing.
 * Returns { appended, skipped, file }. skipped counts local records that are not `feed` records with an indicator.
 * Throws FeedError: exit code 3 when a chain is broken, 1 on any other error. Nothing is written then.
 */
export function publishFeed({ keyId, home = witnessHome(), now = () => new Date() } = {}) {
  if (!keyId) throw new FeedError("--key <key_id> is required");
  const paths = feedPaths(home);
  const sign = signerFor(keyId, home);
  // Every line counts, also a last line with no newline. A broken last line is a broken chain: exit 3, nothing published.
  const local = readChain(paths.local, "refusals.jsonl");
  const localCheck = verifyFeedChain(local, { signed: false, home });
  if (!localCheck.ok) throw new FeedError(`refusals.jsonl is broken: ${localCheck.reason}. Nothing published.`, EXIT.broken);
  mkdirSync(paths.dir, { recursive: true, mode: 0o700 });
  return withChainLock(paths.published, () => {
    const published = readChain(paths.published, "published.jsonl");
    const check = verifyFeedChain(published, { signed: true, home });
    if (!check.ok) throw new FeedError(`published.jsonl is broken: ${check.reason}. Nothing published.`, EXIT.broken);
    const seen = new Set(published.map((r) => r.indicator?.sha256));
    let prev = published.at(-1)?.hash ?? GENESIS;
    let seq = published.length;
    const lines = [];
    let skipped = 0;
    for (const r of local) {
      if (r.event !== "feed" || !validIndicator(r.indicator)) { skipped += 1; continue; }
      if (seen.has(r.indicator.sha256)) continue;
      seen.add(r.indicator.sha256);
      // Copy only the fields of the SPEC-0.2 section 5 table. Nothing else from the local record leaves the machine.
      const origin = { host_sha256: typeof r.origin?.host_sha256 === "string" ? r.origin.host_sha256 : null, session: typeof r.origin?.session === "string" ? r.origin.session : null };
      const sealed = sealRecord({ v: FEED_SCHEMA_VERSION, seq, ts: now().toISOString(), session: PUBLISHED_SESSION, event: "feed", origin, indicator: { kind: r.indicator.kind, sha256: r.indicator.sha256 }, reason: typeof r.reason === "string" ? r.reason : "" }, prev);
      // SPEC-0.2 section 2: the signature covers the hash, so the signer is attached after sealing.
      lines.push(`${JSON.stringify({ ...sealed, signer: sign(sealed.hash) })}\n`);
      prev = sealed.hash;
      seq += 1;
    }
    if (lines.length) appendFileSync(paths.published, lines.join(""), { mode: 0o600 });
    return { appended: lines.length, skipped, file: paths.published };
  });
}

function reply(res, status, body, headers = {}) {
  res.writeHead(status, { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff", ...headers, "content-length": Buffer.byteLength(body) });
  res.end(body);
}

/**
 * Open published.jsonl for serve, never through a link. O_NOFOLLOW refuses a symbolic link (ELOOP).
 * O_NONBLOCK keeps a FIFO from blocking the open. The open file must be a regular file with exactly one hard link,
 * so a hard link to keys/<key_id>.key is refused too. Resolves to { handle, size }, or null when the file does not exist.
 */
async function openPublished(file) {
  let handle;
  try {
    handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  }
  try {
    const stats = await handle.stat();
    if (!stats.isFile()) throw new Error(`${file} is not a regular file`);
    if (stats.nlink !== 1) throw new Error(`${file} has ${stats.nlink} hard links`);
    return { handle, size: stats.size };
  } catch (error) {
    await handle.close();
    throw error;
  }
}

async function readAt(handle, position, length) {
  const buffer = Buffer.alloc(length);
  const { bytesRead } = await handle.read(buffer, 0, length, position);
  return buffer.subarray(0, bytesRead);
}

/**
 * The offset of the first line to serve for ?after=<after>. The leading lines that parse with an integer seq <= after are skipped.
 * From the first other line on, every byte goes out as stored: the server does not verify and does not drop lines.
 * The scan reads in chunks. Memory holds one chunk and one line, and a line longer than MAX_SCAN_LINE ends the scan.
 */
async function startAfter(handle, size, after) {
  let lineStart = 0;
  let carry = Buffer.alloc(0);
  let position = 0;
  while (position < size) {
    const chunk = await readAt(handle, position, Math.min(CHUNK_BYTES, size - position));
    if (chunk.length === 0) break;
    position += chunk.length;
    const data = carry.length ? Buffer.concat([carry, chunk]) : chunk;
    let from = 0;
    for (let nl = data.indexOf(0x0a); nl !== -1; nl = data.indexOf(0x0a, from)) {
      const text = data.subarray(from, nl).toString("utf8");
      if (text.trim() !== "") {
        let seq = null;
        try { seq = JSON.parse(text)?.seq; } catch { /* not JSON: the reply starts here */ }
        if (!Number.isInteger(seq) || seq > after) return lineStart;
      }
      lineStart += nl + 1 - from;
      from = nl + 1;
    }
    carry = Buffer.from(data.subarray(from));
    if (carry.length > MAX_SCAN_LINE) return lineStart;
  }
  return lineStart;
}

/**
 * The end of the last whole line in [start, start + maxBytes) that is also before `size`, or start when there is none.
 * A last line with no newline is still being written, so it is held back.
 */
async function endWithin(handle, size, start, maxBytes) {
  let windowEnd = Math.min(size, start + maxBytes);
  while (windowEnd > start) {
    const from = Math.max(start, windowEnd - CHUNK_BYTES);
    const chunk = await readAt(handle, from, windowEnd - from);
    const nl = chunk.lastIndexOf(0x0a);
    if (nl !== -1) return from + nl + 1;
    windowEnd = from;
  }
  return start;
}

/** Stream the selected byte range of published.jsonl. pipeline() gives backpressure and closes the file when the socket goes. */
async function sendFeed(res, file, after, limits, onWarn) {
  let opened;
  try {
    opened = await openPublished(file);
  } catch (error) {
    onWarn(`not serving ${file}: ${error.code ?? error.message}`);
    return reply(res, 500, "feed unreadable\n");
  }
  const ndjson = { "content-type": "application/x-ndjson", "cache-control": "no-store", "x-content-type-options": "nosniff" };
  if (!opened) return reply(res, 200, "", ndjson);
  const { handle, size } = opened;
  let streaming = false;
  try {
    const start = after === null ? 0 : await startAfter(handle, size, after);
    const end = await endWithin(handle, size, start, limits.maxBytes);
    if (res.destroyed) return;
    res.writeHead(200, { ...ndjson, "content-length": end - start });
    if (end === start) return res.end();
    streaming = true;
    pipeline(handle.createReadStream({ start, end: end - 1 }), res, () => {});
  } finally {
    if (!streaming) await handle.close();
  }
}

/**
 * witness feed serve. A read-only HTTP server bound only to `host`.
 * GET /feed returns published.jsonl as application/x-ndjson, and GET /feed?after=<seq> only the records after seq.
 * A reply holds whole lines only, at most limits.maxBytes; pull again for the rest. A missing published.jsonl gives 200
 * with an empty body. A link or any file that is not a regular file gives 500. A bad `after` gives 400.
 * /feed with another method gives 405. Every other path gives 404. More than limits.maxConcurrent replies at once gives 503.
 * A socket with no traffic for limits.stallMs is destroyed. There is no write endpoint.
 * Resolves to { server, host, port, url, file, close }.
 */
export function startFeedServer({ home = witnessHome(), host = DEFAULT_HOST, port = DEFAULT_PORT, limits = {}, onWarn = () => {} } = {}) {
  const file = feedPaths(home).published;
  const max = { ...SERVE_LIMITS, ...limits };
  let active = 0;
  const server = http.createServer({ requestTimeout: max.stallMs, headersTimeout: max.stallMs, connectionsCheckingInterval: Math.max(100, Math.floor(max.stallMs / 3)) }, (req, res) => {
    const target = req.url ?? "";
    const mark = target.indexOf("?");
    const pathname = mark === -1 ? target : target.slice(0, mark);
    if (pathname !== "/feed") return reply(res, 404, "not found\n");
    if (req.method !== "GET") return reply(res, 405, "method not allowed\n", { allow: "GET" });
    const after = new URLSearchParams(mark === -1 ? "" : target.slice(mark + 1)).get("after");
    if (after !== null && !AFTER_PATTERN.test(after)) return reply(res, 400, "after must be an integer\n");
    if (active >= max.maxConcurrent) return reply(res, 503, "busy\n", { "retry-after": "1" });
    active += 1;
    res.once("close", () => { active -= 1; });
    sendFeed(res, file, after === null ? null : Number(after), max, onWarn).catch((error) => {
      onWarn(`serve failed: ${error.code ?? error.message}`);
      if (!res.headersSent) reply(res, 500, "feed unreadable\n");
      else res.destroy();
    });
  });
  server.maxConnections = max.maxConcurrent * 4;
  // A socket that moves no byte for stallMs is destroyed: a client that stops reading cannot hold a reply open.
  server.setTimeout(max.stallMs, (socket) => socket.destroy());
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => {
      server.off("error", reject);
      const { address, port: bound } = server.address();
      const shown = address.includes(":") ? `[${address}]` : address;
      resolve({ server, host: address, port: bound, url: `http://${shown}:${bound}/feed`, file, close: () => new Promise((done) => { server.close(() => done()); server.closeAllConnections(); }) });
    });
  });
}

/** The peer URL without userinfo, fragment and `after`. It is the key in remote/peers.json. */
function peerUrl(url) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    throw new FeedError("invalid url");
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") throw new FeedError("url must start with http:// or https://");
  parsed.username = "";
  parsed.password = "";
  parsed.hash = "";
  parsed.searchParams.delete("after");
  return parsed.toString();
}

/** remote/peers.json maps a peer URL to the key_id it served. A missing or unreadable file is an empty map: pull finds the peer again. */
function readPeers(file) {
  try {
    const peers = JSON.parse(readFileSync(file, "utf8"));
    return peers && typeof peers === "object" && !Array.isArray(peers) ? peers : {};
  } catch {
    return {};
  }
}

function writePeer(file, url, keyId) {
  const peers = readPeers(file);
  if (peers[url] === keyId) return;
  peers[url] = keyId;
  const temp = `${file}.${process.pid}.tmp`;
  writeFileSync(temp, `${JSON.stringify(peers, null, 2)}\n`, { mode: 0o600 });
  renameSync(temp, file);
}

/** GET url, with ?after=<after> when after is not null. Returns the body as bytes. Network errors are FeedError exit 1. */
async function fetchFeed(url, after, fetchImpl) {
  const target = new URL(url);
  if (after !== null) target.searchParams.set("after", String(after));
  const shown = target.toString();
  let response;
  try {
    response = await fetchImpl(shown, { signal: AbortSignal.timeout(PULL_TIMEOUT_MS) });
  } catch (error) {
    throw new FeedError(`request to ${shown} failed: ${error?.cause?.code ?? error?.cause?.message ?? error?.name ?? "error"}`);
  }
  if (response.status !== 200) throw new FeedError(`request to ${shown} failed: HTTP ${response.status}`);
  const chunks = [];
  let total = 0;
  try {
    for await (const chunk of response.body ?? []) {
      total += chunk.length;
      if (total > MAX_REPLY_BYTES) throw new FeedError(`reply from ${shown} is larger than ${MAX_REPLY_BYTES} bytes`);
      chunks.push(chunk);
    }
  } catch (error) {
    if (error instanceof FeedError) throw error;
    throw new FeedError(`reading the reply from ${shown} failed: ${error?.cause?.code ?? error?.name ?? "error"}`);
  }
  return Buffer.concat(chunks);
}

/** Split bytes into lines on "\n". The empty segment after a final newline is not a line. */
function splitLines(buf) {
  const lines = [];
  let start = 0;
  while (start < buf.length) {
    const end = buf.indexOf(0x0a, start);
    if (end === -1) { lines.push(buf.subarray(start)); break; }
    lines.push(buf.subarray(start, end));
    start = end + 1;
  }
  return lines;
}

/** The key_id the first line claims, or null. Used only to find the local copy. Every line is still checked in full. */
function firstKeyId(buf) {
  const [first] = splitLines(buf);
  try {
    const keyId = JSON.parse(first?.toString("utf8") ?? "")?.signer?.key_id;
    return typeof keyId === "string" && KEY_ID_PATTERN.test(keyId) ? keyId : null;
  } catch {
    return null;
  }
}

/** The last record of the local copy of key_id, after the whole copy verifies. null when there is no copy yet. */
function localHead(keyId, home) {
  const file = remoteFile(keyId, home);
  const records = readChain(file, `remote/${keyId}.jsonl`);
  if (records.length === 0) return null;
  const check = verifyFeedChain(records, { signed: true, keyId, home });
  if (!check.ok) throw new FeedError(`the local copy ${file} is broken: ${check.reason}. Nothing appended.`, EXIT.broken);
  return { seq: records.at(-1).seq, hash: records.at(-1).hash };
}

/**
 * Check one line from a peer, in the order of the feed contract. Returns { record, keyId } or { problem }.
 * expect: { keyId, seq, prev }. keyId is null until the first line of a new peer names it.
 */
function checkLine(bytes, expect, home) {
  const text = bytes.toString("utf8");
  if (!Buffer.from(text, "utf8").equals(bytes)) return { problem: "is not valid UTF-8" };
  let record;
  try { record = JSON.parse(text); } catch { return { problem: "is not JSON" }; }
  if (!record || typeof record !== "object" || Array.isArray(record)) return { problem: "is not a JSON object" };
  if (record.event !== "feed") return { problem: `has event ${JSON.stringify(record.event)}, not "feed"` };
  const { signer, ...body } = record;
  if (!signer || typeof signer !== "object") return { problem: "has no signer" };
  if (typeof signer.key_id !== "string" || !KEY_ID_PATTERN.test(signer.key_id)) return { problem: "has an invalid signer.key_id" };
  if (expect.keyId && signer.key_id !== expect.keyId) return { problem: `is signed by ${signer.key_id}, but this peer is ${expect.keyId}` };
  const trust = trustedKey(signer.key_id, home);
  if (trust.problem) return { problem: `cannot be trusted: ${trust.problem}` };
  if (typeof body.prev !== "string" || hashRecord(body, body.prev) !== body.hash) return { problem: "has a hash that does not match its content" };
  const bad = checkSigner(body.hash, signer, () => trust.pem);
  if (bad) return { problem: `has a ${bad}` };
  if (body.seq !== expect.seq) return { problem: `has seq ${body.seq}, but the local copy needs seq ${expect.seq}` };
  if (body.prev !== expect.prev) return { problem: "has a prev that does not continue the local copy" };
  // The council gate fails closed on a line without an indicator, so such a line never enters a remote copy.
  if (!validIndicator(body.indicator)) return { problem: "has no valid indicator.kind and indicator.sha256" };
  return { record: body, keyId: signer.key_id };
}

/**
 * witness feed pull <url>. Ask the peer for the records after the last seq in the local copy, check each line in order,
 * and append the lines that pass, byte for byte, to remote/<key_id>.jsonl.
 * At the first line that fails, keep the lines before it, append nothing after it, and throw FeedError with exit code 3.
 * Network and file errors throw FeedError with exit code 1. Returns { appended, keyId, file }.
 */
export async function pullFeed({ url, home = witnessHome(), fetchImpl = globalThis.fetch } = {}) {
  if (!url) throw new FeedError("<url> is required");
  const peer = peerUrl(url);
  const paths = feedPaths(home);
  let keyId = readPeers(paths.peers)[peer] ?? null;
  if (typeof keyId !== "string" || !KEY_ID_PATTERN.test(keyId)) keyId = null;
  let head = keyId ? localHead(keyId, home) : null;
  let reply = await fetchFeed(peer, head ? head.seq : null, fetchImpl);
  if (keyId === null) {
    // This URL is new to this home. The first line names the peer key. When a copy of that key exists, ask again with ?after=.
    const named = firstKeyId(reply);
    if (named && existsSync(remoteFile(named, home))) {
      keyId = named;
      head = localHead(keyId, home);
      if (head) reply = await fetchFeed(peer, head.seq, fetchImpl);
    }
  }
  const lines = splitLines(reply);
  const accepted = [];
  let expect = { keyId, seq: head ? head.seq + 1 : 0, prev: head ? head.hash : GENESIS };
  let failure = null;
  for (let i = 0; i < lines.length; i += 1) {
    const result = checkLine(lines[i], expect, home);
    if (result.problem) { failure = `line ${i + 1} of the reply ${result.problem}`; break; }
    accepted.push(lines[i]);
    expect = { keyId: result.keyId, seq: result.record.seq + 1, prev: result.record.hash };
  }
  keyId = expect.keyId;
  const file = keyId ? remoteFile(keyId, home) : null;
  if (accepted.length) {
    mkdirSync(paths.remote, { recursive: true, mode: 0o700 });
    withChainLock(file, () => {
      // Another pull may have appended since this one read the head. Then these lines no longer continue the copy.
      if ((localHead(keyId, home)?.hash ?? null) !== (head?.hash ?? null)) throw new FeedError(`${file} changed during this pull. Nothing appended. Run pull again.`);
      appendFileSync(file, Buffer.concat(accepted.flatMap((line) => [line, NEWLINE])), { mode: 0o600 });
    });
  }
  if (keyId && (accepted.length || head)) writePeer(paths.peers, peer, keyId);
  if (failure) throw new FeedError(`${failure}. Kept ${accepted.length} line(s) before it.`, EXIT.broken, { appended: accepted.length, keyId, file });
  return { appended: accepted.length, keyId, file };
}

/**
 * witness feed match <sha256>. Look in refusals.jsonl, published.jsonl and every remote/*.jsonl.
 * A hit counts only from a file that verifies. refusals.jsonl: a valid chain. published.jsonl: a valid chain with every
 * record signed by a trusted key in keys/. remote/<key_id>.jsonl: a valid chain with every record signed by
 * keys/<key_id>.pub. Only ENOENT means a missing file or directory.
 * Returns { code, hits: [{ file, kind }], errors }. code is 0 when found, 1 when not found, 2 on any error:
 * a malformed <sha256>, a file or directory that cannot be read, a line that does not parse, or a file that does not verify.
 * An error wins over a hit, so a gate that reads the code fails closed.
 */
export function matchFeed(sha256, home = witnessHome()) {
  if (typeof sha256 !== "string" || !/^[0-9a-fA-F]{64}$/.test(sha256)) return { code: 2, hits: [], errors: ["<sha256> must be 64 hex characters"] };
  const want = sha256.toLowerCase();
  const paths = feedPaths(home);
  const errors = [];
  const files = [{ file: paths.local, rule: { signed: false, keyId: null } }, { file: paths.published, rule: { signed: true, keyId: null } }];
  try {
    for (const name of readdirSync(paths.remote).filter((n) => n.endsWith(".jsonl")).sort()) {
      files.push({ file: path.join(paths.remote, name), rule: { signed: true, keyId: path.basename(name, ".jsonl") } });
    }
  } catch (error) {
    if (error.code !== "ENOENT") errors.push(`${paths.remote} cannot be read (${error.code ?? error.message})`);
  }
  const hits = [];
  for (const { file, rule } of files) {
    let text;
    try {
      text = readFileSync(file, "utf8");
    } catch (error) {
      if (error.code !== "ENOENT") errors.push(`${file} cannot be read (${error.code ?? error.message})`);
      continue;
    }
    let records;
    try {
      records = parseChain(text, path.basename(file));
    } catch (error) {
      errors.push(error.message);
      continue;
    }
    const check = verifyFeedChain(records, { ...rule, home });
    if (!check.ok) { errors.push(`${file} does not verify: ${check.reason}`); continue; }
    const hit = records.find((r) => r.indicator?.sha256 === want);
    if (hit) hits.push({ file, kind: String(hit.indicator.kind ?? "?") });
  }
  return { code: errors.length ? 2 : hits.length ? 0 : 1, hits, errors };
}
