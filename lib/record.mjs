// Witness record schema v0.1 — canonical serialization + hash chain.
// hash = sha256(canonical(record without hash) + prev). Canonical = keys sorted, no whitespace.
import { createHash, createPublicKey, verify as edVerify } from "node:crypto";

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

/**
 * Walk a list of records; returns { ok, count, brokenAt, reason }.
 * A top-level `signer` (SPEC-0.2.md section 2) is attached after hashing, so it is removed before the hash check.
 * This walk does not check the signature itself.
 */
export function verifyChain(records, { publicKeys = null } = {}) {
  let prev = GENESIS;
  for (let index = 0; index < records.length; index += 1) {
    const { signer, ...record } = records[index];
    if (record.prev !== prev) return { ok: false, count: index, brokenAt: index, reason: `prev mismatch at seq ${record.seq ?? index}` };
    if (hashRecord(record, prev) !== record.hash) return { ok: false, count: index, brokenAt: index, reason: `hash mismatch at seq ${record.seq ?? index}` };
    if (signer) {
      const bad = checkSigner(record.hash, signer, publicKeys);
      if (bad) return { ok: false, count: index, brokenAt: index, reason: `${bad} at seq ${record.seq ?? index}` };
    }
    prev = record.hash;
  }
  return { ok: true, count: records.length, brokenAt: null, reason: null };
}

/**
 * Check a record's signer block against the hash it claims to sign.
 * publicKeys: a function key_id -> PEM string or null, or a plain object. When no key is known for key_id
 * the signature cannot be checked and the record is reported as unverifiable, which breaks the walk:
 * a signer block that nobody can check is not evidence.
 */
export function checkSigner(hash, signer, publicKeys) {
  if (!signer || typeof signer !== "object") return "malformed signer";
  if (signer.alg !== "ed25519" || typeof signer.key_id !== "string" || typeof signer.sig !== "string") return "malformed signer";
  const pem = typeof publicKeys === "function" ? publicKeys(signer.key_id) : publicKeys?.[signer.key_id] ?? null;
  if (!pem) return `no public key for ${signer.key_id}`;
  try {
    const ok = edVerify(null, Buffer.from(hash, "hex"), createPublicKey(pem), Buffer.from(signer.sig, "base64"));
    return ok ? null : "bad signature";
  } catch (error) {
    return `signature check failed: ${error.message}`;
  }
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
