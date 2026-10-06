// witness feed: a signed relay of refusal indicators between Witness homes. Format v0.2, see SPEC-0.2.md sections 2 and 5.
// The council mod writes feed/refusals.jsonl. This file only reads it.
// publish writes feed/published.jsonl. pull writes feed/remote/<key_id>.jsonl and feed/remote/peers.json. serve writes nothing.
import { createPrivateKey } from "node:crypto";
import { appendFileSync, constants, mkdirSync, readFileSync, readdirSync, renameSync, writeFileSync } from "node:fs";
import { lookup } from "node:dns/promises";
import { open } from "node:fs/promises";
import http from "node:http";
import net from "node:net";
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

/** Format an untrusted value for a message. It never throws: JSON.stringify runs inside a try. */
export function show(value) {
  try {
    return JSON.stringify(value) ?? typeof value;
  } catch {
    return "[unprintable]";
  }
}

function validIndicator(indicator) {
  return Boolean(indicator) && typeof indicator.kind === "string" && indicator.kind !== "" && typeof indicator.sha256 === "string" && SHA256_PATTERN.test(indicator.sha256);
}

/**
 * Parse chain text into records. A line that is not a JSON object throws a FeedError with exit code 3.
 * An empty or whitespace-only line is a bad line too. Only the empty element after a final newline is dropped,
 * so an empty file is an empty chain. A last line with no newline is parsed and checked like every other line.
 */
function parseChain(text, label) {
  const lines = text.split("\n");
  if (lines.at(-1) === "") lines.pop();
  const records = [];
  for (let i = 0; i < lines.length; i += 1) {
    if (lines[i].trim() === "") throw new FeedError(`${label} line ${i + 1} is blank`, EXIT.broken);
    let record;
    try { record = JSON.parse(lines[i]); } catch { record = null; }
    if (!record || typeof record !== "object" || Array.isArray(record)) throw new FeedError(`${label} line ${i + 1} is not a JSON object`, EXIT.broken);
    records.push(record);
  }
  return records;
}

const UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/** Decode bytes as UTF-8. Any invalid byte fails: nothing is repaired with U+FFFD, and a BOM is kept. FeedError with exitCode. */
function decodeUtf8(bytes, label, exitCode = EXIT.broken) {
  try {
    return UTF8.decode(bytes);
  } catch {
    throw new FeedError(`${label} is not valid UTF-8`, exitCode);
  }
}

/**
 * Read a feed file as text with the fatal decoder. null when the file does not exist (ENOENT only).
 * Any other read error is FeedError exit 1. Invalid UTF-8 is FeedError exit 3.
 */
function readFeedText(file, label) {
  let bytes;
  try {
    bytes = readFileSync(file);
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw new FeedError(`cannot read ${file}: ${error.code ?? error.message}`);
  }
  return decodeUtf8(bytes, label);
}

/** Read and parse a chain file. A missing file is an empty chain. Read errors are exit 1; invalid UTF-8 and bad lines are exit 3. */
function readChain(file, label) {
  const text = readFeedText(file, label);
  return text === null ? [] : parseChain(text, label);
}

/** The key_id that a remote copy's file name gives: the name without ".jsonl". It is "" for a file named ".jsonl". */
export function remoteKeyId(name) {
  return name.endsWith(".jsonl") ? name.slice(0, -".jsonl".length) : name;
}

/**
 * Read a feed file for witness verify with the strict parser. Returns { records, problem }.
 * problem is set for a blank or unparseable line and for a read error other than ENOENT. A missing file is an empty chain.
 */
export function readFeedFile(file) {
  try {
    return { records: readChain(file, path.basename(file)), problem: null };
  } catch (error) {
    return { records: [], problem: error.message };
  }
}

/**
 * The feed rules for a chain file, from its path and its records. null when the file is not a feed chain.
 * signed: every record needs a valid signer. keyId: every signer must be this key, because a remote copy holds one peer.
 * For a remote copy keyId comes from the file name, and verifyFeedChain fails it unless it matches KEY_ID_PATTERN.
 */
export function feedChainRule(file, records = []) {
  const name = path.basename(file);
  const parent = path.basename(path.dirname(file));
  const grandparent = path.basename(path.dirname(path.dirname(file)));
  if (parent === "remote" && grandparent === "feed") return { signed: true, keyId: remoteKeyId(name) };
  if (name === "published.jsonl" || records.some((r) => r?.session === PUBLISHED_SESSION)) return { signed: true, keyId: null };
  if (name === "refusals.jsonl" && parent === "feed") return { signed: false, keyId: null };
  return null;
}

/**
 * Verify one feed file as one chain. On top of verifyChain: seq equals the position in the file,
 * a signed chain holds only `feed` records and every one has a signer, and a remote copy holds one key_id.
 * keyId null means no key rule. Any other keyId must match KEY_ID_PATTERN, or the file fails before its first record,
 * also when it is empty. Every record's signer.key_id must then equal keyId exactly.
 * Signers are checked with trustedKeyLoader: a .pub counts only when it hashes to its key_id.
 * Every check runs inside one guard. An exception anywhere in the walk (for example a record nested too deep to hash,
 * or a field that cannot be turned into text) is a broken chain, not a crash. Untrusted values are formatted with show().
 */
export function verifyFeedChain(records, { signed = false, keyId = null, home = witnessHome() } = {}) {
  try {
    if (keyId !== null && !(typeof keyId === "string" && KEY_ID_PATTERN.test(keyId))) {
      return { ok: false, count: 0, brokenAt: 0, reason: `the file name ${show(`${keyId}.jsonl`)} is not <key_id>.jsonl` };
    }
    const chain = verifyChain(records, { publicKeys: trustedKeyLoader(home), requireSigner: signed });
    const end = chain.ok ? records.length : chain.brokenAt;
    for (let i = 0; i < end; i += 1) {
      const record = records[i];
      const fail = (reason) => ({ ok: false, count: i, brokenAt: i, reason });
      if (record.seq !== i) return fail(`seq ${show(record.seq)} at position ${i}`);
      if (signed && record.event !== "feed") return fail(`event ${show(record.event)} at seq ${i}, expected "feed"`);
      if (keyId !== null && record.signer?.key_id !== keyId) return fail(`signer ${show(record.signer?.key_id)} at seq ${i} in the copy of ${keyId}`);
    }
    return chain;
  } catch (error) {
    const plain = (value) => (typeof value === "string" ? value : show(value));
    return { ok: false, count: 0, brokenAt: 0, reason: `cannot be checked (${plain(error?.name)}: ${plain(error?.message)})` };
  }
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
    const text = readFeedText(paths.published, "published.jsonl") ?? "";
    // An append to a last line with no newline would join two records on one line. Refuse it.
    if (text !== "" && !text.endsWith("\n")) throw new FeedError("published.jsonl does not end with a newline. Nothing published.", EXIT.broken);
    const published = parseChain(text, "published.jsonl");
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
 * Open published.jsonl for serve. O_NOFOLLOW refuses a symbolic link at the last path component (ELOOP).
 * O_NONBLOCK keeps a FIFO from blocking the open. The open file must be a regular file with exactly one hard link,
 * so a hard link to keys/<key_id>.key is refused too. Resolves to { handle, size }, or null when the file does not exist.
 * load.handles counts the open handles; the caller closes the handle with closePublished.
 */
async function openPublished(file, load) {
  let handle;
  try {
    handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  }
  load.handles += 1;
  try {
    const stats = await handle.stat();
    if (!stats.isFile()) throw new Error(`${file} is not a regular file`);
    if (stats.nlink !== 1) throw new Error(`${file} has ${stats.nlink} hard links`);
    return { handle, size: stats.size };
  } catch (error) {
    await closePublished(handle, load);
    throw error;
  }
}

/** Close a handle from openPublished. FileHandle.close waits for any read still in flight on it. */
async function closePublished(handle, load) {
  try {
    await handle.close();
  } finally {
    load.handles -= 1;
  }
}

/** Throw when the reply's response or socket has closed, so a scan stops at its next chunk. */
function stopIfClosed(signal) {
  if (signal.aborted) throw Object.assign(new Error("the client closed the reply"), { code: "ABORT_ERR" });
}

async function readAt(handle, position, length) {
  const buffer = Buffer.alloc(length);
  const { bytesRead } = await handle.read(buffer, 0, length, position);
  return buffer.subarray(0, bytesRead);
}

/**
 * The offset of the first line to serve for ?after=<after>. The leading lines that parse with an integer seq <= after are skipped.
 * A blank line stops the skip like any line that does not parse.
 * From the first other line on, every byte goes out as stored: the server does not verify and does not drop lines.
 * The scan reads in chunks. Memory holds one chunk and one line, and a line longer than MAX_SCAN_LINE ends the scan.
 */
async function startAfter(handle, size, after, signal) {
  let lineStart = 0;
  let carry = Buffer.alloc(0);
  let position = 0;
  while (position < size) {
    stopIfClosed(signal);
    const chunk = await readAt(handle, position, Math.min(CHUNK_BYTES, size - position));
    if (chunk.length === 0) break;
    position += chunk.length;
    const data = carry.length ? Buffer.concat([carry, chunk]) : chunk;
    let from = 0;
    for (let nl = data.indexOf(0x0a); nl !== -1; nl = data.indexOf(0x0a, from)) {
      const text = data.subarray(from, nl).toString("utf8");
      // A blank or unparseable line is not skipped: the reply starts there, so pull sees it and rejects it.
      let seq = null;
      try { seq = JSON.parse(text)?.seq; } catch { /* not JSON: the reply starts here */ }
      if (!Number.isInteger(seq) || seq > after) return lineStart;
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
async function endWithin(handle, size, start, maxBytes, signal) {
  let windowEnd = Math.min(size, start + maxBytes);
  while (windowEnd > start) {
    stopIfClosed(signal);
    const from = Math.max(start, windowEnd - CHUNK_BYTES);
    const chunk = await readAt(handle, from, windowEnd - from);
    const nl = chunk.lastIndexOf(0x0a);
    if (nl !== -1) return from + nl + 1;
    windowEnd = from;
  }
  return start;
}

/**
 * Stream the selected byte range of published.jsonl. pipeline() gives backpressure.
 * The promise settles only after the scan has stopped, the stream has ended or failed, and the file handle is closed,
 * so the caller can hold its concurrency slot until then. signal aborts when the response or its socket closes.
 */
async function sendFeed(res, file, after, limits, onWarn, signal, load) {
  let opened;
  try {
    opened = await openPublished(file, load);
  } catch (error) {
    onWarn(`not serving ${file}: ${error.code ?? error.message}`);
    return reply(res, 500, "feed unreadable\n");
  }
  const ndjson = { "content-type": "application/x-ndjson", "cache-control": "no-store", "x-content-type-options": "nosniff" };
  if (!opened) return reply(res, 200, "", ndjson);
  const { handle, size } = opened;
  try {
    let start;
    let end;
    load.scans += 1;
    try {
      start = after === null ? 0 : await startAfter(handle, size, after, signal);
      end = await endWithin(handle, size, start, limits.maxBytes, signal);
    } finally {
      load.scans -= 1;
    }
    stopIfClosed(signal);
    res.writeHead(200, { ...ndjson, "content-length": end - start });
    if (end === start) return res.end();
    // autoClose is off: the handle closes below, after the stream is done, and close waits for a read in flight.
    await new Promise((done) => pipeline(handle.createReadStream({ start, end: end - 1, autoClose: false }), res, () => done()));
  } finally {
    await closePublished(handle, load);
  }
}

/** True for an address that means every interface: 0.0.0.0, ::, any all-zero IPv6 form, and ::ffff:0.0.0.0. */
export function isUnspecifiedAddress(address) {
  if (net.isIPv4(address)) return address === "0.0.0.0";
  if (!net.isIPv6(address)) return false;
  const lower = address.toLowerCase();
  if (lower.startsWith("::ffff:") && net.isIPv4(lower.slice(7))) return lower.slice(7) === "0.0.0.0";
  return lower.split(":").every((part) => /^0*$/.test(part));
}

/**
 * Check --host and resolve it to the one address serve binds. An empty, whitespace or non-string host is refused,
 * because Node binds "" to every interface. A host that resolves to an unspecified address (0.0.0.0, ::, "0", "0x0")
 * is refused unless anyInterface is true. Brackets around an IPv6 address are removed. Throws FeedError exit 1.
 */
export async function resolveServeHost(host, { anyInterface = false } = {}) {
  if (typeof host !== "string" || host.trim() === "" || /\s/.test(host)) {
    throw new FeedError(`--host must be a host name or an address, not ${show(host)}`);
  }
  const name = host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
  let address;
  try {
    ({ address } = await lookup(name, { verbatim: true }));
  } catch (error) {
    throw new FeedError(`cannot resolve --host ${show(host)}: ${error.code ?? error.message}`);
  }
  if (isUnspecifiedAddress(address) && !anyInterface) {
    throw new FeedError(`--host ${show(host)} means every interface (${address}). Pass --any-interface as well to allow it.`);
  }
  return address;
}

/**
 * witness feed serve. A read-only HTTP server bound only to `host`, after resolveServeHost checked it.
 * GET /feed returns published.jsonl as application/x-ndjson, and GET /feed?after=<seq> only the records after seq.
 * A reply holds whole lines only, at most limits.maxBytes; pull again for the rest. A missing published.jsonl gives 200
 * with an empty body. A link or any file that is not a regular file gives 500. A bad `after` gives 400.
 * /feed with another method gives 405. Every other path gives 404. More than limits.maxConcurrent replies at once gives 503.
 * A socket with no traffic for limits.stallMs is destroyed. There is no write endpoint.
 * A slot is taken per reply and given back only when its scan, its stream and its file handle are all done.
 * When a client goes away during the scan, the scan stops at its next chunk.
 * Resolves to { server, host, port, url, file, close, load }. load() returns { replies, scans, handles } now in use.
 */
export async function startFeedServer({ home = witnessHome(), host = DEFAULT_HOST, port = DEFAULT_PORT, anyInterface = false, limits = {}, onWarn = () => {} } = {}) {
  const address = await resolveServeHost(host, { anyInterface });
  const file = feedPaths(home).published;
  const max = { ...SERVE_LIMITS, ...limits };
  let active = 0;
  const load = { scans: 0, handles: 0 };
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
    const closed = new AbortController();
    res.once("close", () => closed.abort());
    sendFeed(res, file, after === null ? null : Number(after), max, onWarn, closed.signal, load)
      .catch((error) => {
        if (closed.signal.aborted) return;
        onWarn(`serve failed: ${error.code ?? error.message}`);
        if (!res.headersSent) reply(res, 500, "feed unreadable\n");
        else res.destroy();
      })
      .finally(() => { active -= 1; });
  });
  server.maxConnections = max.maxConcurrent * 4;
  // A socket that moves no byte for stallMs is destroyed: a client that stops reading cannot hold a reply open.
  server.setTimeout(max.stallMs, (socket) => socket.destroy());
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, address, () => {
      server.off("error", reject);
      const { address: boundAddress, port: bound } = server.address();
      const shown = boundAddress.includes(":") ? `[${boundAddress}]` : boundAddress;
      resolve({ server, host: boundAddress, port: bound, url: `http://${shown}:${bound}/feed`, file, close: () => new Promise((done) => { server.close(() => done()); server.closeAllConnections(); }), load: () => ({ replies: active, ...load }) });
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

/**
 * remote/peers.json maps a peer URL to the key_id it served. Only ENOENT means an empty map.
 * Any other read error, text that is not a JSON object, or a value that is not a key_id is FeedError exit 1.
 */
function readPeers(file) {
  let bytes;
  try {
    bytes = readFileSync(file);
  } catch (error) {
    if (error.code === "ENOENT") return {};
    throw new FeedError(`cannot read ${file}: ${error.code ?? error.message}. Nothing changed.`);
  }
  const text = decodeUtf8(bytes, `${file} (nothing changed)`, EXIT.error);
  let peers;
  try { peers = JSON.parse(text); } catch { peers = null; }
  if (!peers || typeof peers !== "object" || Array.isArray(peers)) throw new FeedError(`${file} is not a JSON object. Nothing changed.`);
  for (const [url, keyId] of Object.entries(peers)) {
    if (typeof keyId !== "string" || !KEY_ID_PATTERN.test(keyId)) throw new FeedError(`${file} binds ${show(url)} to ${show(keyId)}, which is not a key_id. Nothing changed.`);
  }
  return peers;
}

/**
 * Write peers with url bound to keyId. peers is the map pull read before its request, so a file error stops pull
 * before it changes anything. Two pulls at once can lose one new binding; the next pull of that URL finds the peer again.
 */
function writePeer(file, peers, url, keyId) {
  if (peers[url] === keyId) return;
  const temp = `${file}.${process.pid}.tmp`;
  writeFileSync(temp, `${JSON.stringify({ ...peers, [url]: keyId }, null, 2)}\n`, { mode: 0o600 });
  renameSync(temp, file);
}

/**
 * One GET to url, with ?after=<after> when after is not null. No redirect is followed.
 * Returns the body as bytes. Network errors, a redirect and a status other than 200 are FeedError exit 1.
 */
async function fetchFeed(url, after, fetchImpl) {
  const target = new URL(url);
  if (after !== null) target.searchParams.set("after", String(after));
  const shown = target.toString();
  let response;
  try {
    response = await fetchImpl(shown, { redirect: "error", signal: AbortSignal.timeout(PULL_TIMEOUT_MS) });
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

/** Split a reply into its complete lines and the bytes after the last newline. */
function splitReply(buf) {
  const end = buf.lastIndexOf(0x0a) + 1;
  return { lines: splitLines(buf.subarray(0, end)), tail: buf.subarray(end) };
}

/** The key_id that a line claims, or null. Used only to find a local copy to compare against. */
function claimedKeyId(line) {
  if (!line) return null;
  try {
    const keyId = JSON.parse(line.toString("utf8"))?.signer?.key_id;
    return typeof keyId === "string" && KEY_ID_PATTERN.test(keyId) ? keyId : null;
  } catch {
    return null;
  }
}

/**
 * The local copy of key_id: its lines as stored and its last seq and hash, after the whole copy verifies.
 * null when there is no copy or it is empty. A copy that does not verify, or whose last line has no newline, is FeedError exit 3.
 */
function localCopy(keyId, home) {
  const file = remoteFile(keyId, home);
  let bytes;
  try {
    bytes = readFileSync(file);
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw new FeedError(`cannot read ${file}: ${error.code ?? error.message}`);
  }
  if (bytes.length === 0) return null;
  const broken = (reason) => new FeedError(`the local copy ${file} is broken: ${reason}. Nothing appended.`, EXIT.broken);
  if (bytes.at(-1) !== 0x0a) throw broken("its last line has no newline");
  const lines = splitLines(bytes);
  // parseChain throws exit 3 on a blank or unparseable line, so records and lines match one to one.
  const records = parseChain(decodeUtf8(bytes, `the local copy ${file}`), `remote/${keyId}.jsonl`);
  const check = verifyFeedChain(records, { signed: true, keyId, home });
  if (!check.ok) throw broken(check.reason);
  return { lines, seq: records.at(-1).seq, hash: records.at(-1).hash };
}

/**
 * Check one new line from a peer, in the order of the feed contract. Returns { record, keyId } or { problem }.
 * expect: { keyId, seq, prev }. keyId is null until the first line of a new peer names it.
 * Any exception counts as a failed line (for example a record nested too deep to hash).
 */
function checkLine(bytes, expect, home) {
  try {
    return checkLineFields(bytes, expect, home);
  } catch (error) {
    return { problem: `cannot be checked (${error.name}: ${error.message})` };
  }
}

function checkLineFields(bytes, expect, home) {
  let text;
  try { text = UTF8.decode(bytes); } catch { return { problem: "is not valid UTF-8" }; }
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
  if (body.seq !== expect.seq) return { problem: `has seq ${show(body.seq)}, but the local copy needs seq ${expect.seq}` };
  if (body.prev !== expect.prev) return { problem: "has a prev that does not continue the local copy" };
  // The council gate fails closed on a line without an indicator, so such a line never enters a remote copy.
  if (!validIndicator(body.indicator)) return { problem: "has no valid indicator.kind and indicator.sha256" };
  return { record: body, keyId: signer.key_id };
}

/**
 * witness feed pull <url>. Send one GET and check the whole reply.
 * A URL bound in remote/peers.json to a local copy asks for ?after=<last seq of that copy>; every line must be new.
 * Any other URL asks for the whole feed. When its first line names a key with a local copy, the reply must repeat that
 * copy byte for byte before its new lines. Every new line must pass checkLine and continue the chain.
 * A reply that ends without a newline fails at its last line. The lines that pass are appended byte for byte to
 * remote/<key_id>.jsonl. At the first line that fails: keep the new lines before it, append nothing after it, and throw
 * FeedError exit 3. Network and file errors throw FeedError exit 1. Returns { appended, keyId, file }.
 */
export async function pullFeed({ url, home = witnessHome(), fetchImpl = globalThis.fetch } = {}) {
  if (!url) throw new FeedError("<url> is required");
  const peer = peerUrl(url);
  const paths = feedPaths(home);
  // Read the bindings before the request: a peers.json that cannot be read or holds bad data stops pull with exit 1.
  const peers = readPeers(paths.peers);
  const bound = Object.hasOwn(peers, peer) ? peers[peer] : null;
  const boundCopy = bound ? localCopy(bound, home) : null;
  const { lines, tail } = splitReply(await fetchFeed(peer, boundCopy ? boundCopy.seq : null, fetchImpl));
  let keyId = bound;
  let copy = boundCopy;
  let overlap = [];
  if (!boundCopy) {
    // The reply starts at seq 0. If it names a key that has a local copy, its first lines must be that copy.
    const named = bound ?? claimedKeyId(lines[0]);
    copy = named ? localCopy(named, home) : null;
    if (copy) { keyId = named; overlap = copy.lines; }
  }
  const accepted = [];
  let expect = copy ? { keyId, seq: copy.seq + 1, prev: copy.hash } : { keyId, seq: 0, prev: GENESIS };
  let failure = null;
  let overlapOk = true;
  for (let i = 0; i < lines.length && failure === null; i += 1) {
    if (i < overlap.length) {
      if (!lines[i].equals(overlap[i])) { failure = `line ${i + 1} of the reply differs from line ${i + 1} of the local copy of ${keyId}`; overlapOk = false; }
      continue;
    }
    const result = checkLine(lines[i], expect, home);
    if (result.problem) { failure = `line ${i + 1} of the reply ${result.problem}`; continue; }
    accepted.push(lines[i]);
    expect = { keyId: result.keyId, seq: result.record.seq + 1, prev: result.record.hash };
  }
  if (failure === null && tail.length) failure = `line ${lines.length + 1} of the reply has no newline at the end`;
  keyId = expect.keyId;
  const file = keyId ? remoteFile(keyId, home) : null;
  if (accepted.length) {
    mkdirSync(paths.remote, { recursive: true, mode: 0o700 });
    withChainLock(file, () => {
      // Another pull may have appended since this one read the copy. Then these lines no longer continue it.
      if ((localCopy(keyId, home)?.hash ?? null) !== (copy?.hash ?? null)) throw new FeedError(`${file} changed during this pull. Nothing appended. Run pull again.`);
      appendFileSync(file, Buffer.concat(accepted.flatMap((line) => [line, NEWLINE])), { mode: 0o600 });
    });
  }
  // Bind the URL to the key once the reply extended the copy, or repeated it without a difference.
  if (keyId && (accepted.length || (copy && overlapOk))) writePeer(paths.peers, peers, peer, keyId);
  if (failure) throw new FeedError(`${failure}. Kept ${accepted.length} new line(s) before it.`, EXIT.broken, { appended: accepted.length, keyId, file });
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
      // Every *.jsonl name counts, also ".jsonl" or "x.jsonl": verifyFeedChain fails a name that is not <key_id>.jsonl.
      files.push({ file: path.join(paths.remote, name), rule: { signed: true, keyId: remoteKeyId(name) } });
    }
  } catch (error) {
    if (error.code !== "ENOENT") errors.push(`${paths.remote} cannot be read (${error.code ?? error.message})`);
  }
  const hits = [];
  for (const { file, rule } of files) {
    let bytes;
    try {
      bytes = readFileSync(file);
    } catch (error) {
      if (error.code !== "ENOENT") errors.push(`${file} cannot be read (${error.code ?? error.message})`);
      continue;
    }
    let records;
    try {
      records = parseChain(decodeUtf8(bytes, file), path.basename(file));
    } catch (error) {
      errors.push(error.message);
      continue;
    }
    const check = verifyFeedChain(records, { ...rule, home });
    if (!check.ok) { errors.push(`${file} does not verify: ${check.reason}`); continue; }
    const hit = records.find((r) => r.indicator?.sha256 === want);
    if (hit) hits.push({ file, kind: typeof hit.indicator.kind === "string" ? hit.indicator.kind : show(hit.indicator.kind) });
  }
  return { code: errors.length ? 2 : hits.length ? 0 : 1, hits, errors };
}
