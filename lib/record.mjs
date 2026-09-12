// Witness record schema v0.1 — canonical serialization + hash chain.
// hash = sha256(canonical(record without hash) + prev). Canonical = keys sorted, no whitespace.
import { createHash } from "node:crypto";

export const SCHEMA_VERSION = "0.1";
export const GENESIS = "GENESIS";

export function sha256(input) {
  return createHash("sha256").update(input).digest("hex");
}

export function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

export function hashRecord(record, prev) {
  const { hash: _ignored, ...body } = record;
  return sha256(canonical(body) + prev);
}

export function sealRecord(record, prev) {
  const body = { ...record, prev };
  return { ...body, hash: hashRecord(body, prev) };
}

/** Walk a list of records; returns { ok, count, brokenAt, reason }. */
export function verifyChain(records) {
  let prev = GENESIS;
  for (let index = 0; index < records.length; index += 1) {
    const record = records[index];
    if (record.prev !== prev) return { ok: false, count: index, brokenAt: index, reason: `prev mismatch at seq ${record.seq ?? index}` };
    if (hashRecord(record, prev) !== record.hash) return { ok: false, count: index, brokenAt: index, reason: `hash mismatch at seq ${record.seq ?? index}` };
    prev = record.hash;
  }
  return { ok: true, count: records.length, brokenAt: null, reason: null };
}

/** Default privacy posture: digest, don't store. Only allow-listed keys are summarised in plaintext. */
const DENY_KEY = /token|secret|password|authorization|cookie|api[_-]?key|credential/i;

export function digestArgs(args, allowKeys = []) {
  const text = canonical(args ?? null);
  const summary = {};
  if (args && typeof args === "object" && !Array.isArray(args)) {
    for (const key of allowKeys) {
      if (key in args && !DENY_KEY.test(key)) {
        const value = args[key];
        summary[key] = typeof value === "string" ? value.slice(0, 120) : typeof value === "number" || typeof value === "boolean" ? value : "[omitted]";
      }
    }
  }
  return { sha256: sha256(text), bytes: Buffer.byteLength(text), summary: Object.keys(summary).length ? summary : undefined };
}
