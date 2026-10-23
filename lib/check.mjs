// witness check: the offline verifier for a countersigned session. Format v0.4, see SPEC-0.4.md section 4.
// It reads only log/<session>.jsonl, heads/<session>.jsonl, receipts/<session>.jsonl and keys/*.pub under one home,
// so an outside party can run it on copies of those files. It writes nothing and opens no socket.
import { createPublicKey } from "node:crypto";
import { checkHead, headDigest, readHeads, readSessionChain, validSession } from "./heads.mjs";
import { KEY_ID_PATTERN, trustedKey } from "./keys.mjs";
import { checkReceipt, readReceipts, receiptMatches } from "./notary.mjs";
import { witnessHome } from "./session-log.mjs";

/** Exit codes of witness check. With several failures the code is the one of the first failure, in the order the checks run. */
export const CHECK_EXIT = Object.freeze({
  ok: 0,
  error: 1, // bad arguments, a missing file, or a line that does not parse
  chain: 2, // the session chain is broken
  head: 3, // a head does not match the chain (wrong hash at its seq, seq past the end, another session)
  headSignature: 4, // a head is malformed, its key_id does not match its public_key, its signature fails, or it is not the --operator key
  receiptSignature: 5, // a receipt is malformed, not signed by the --notary key, the key is not trusted, or hash or signature fails
  receiptHead: 6, // a receipt does not name a head in heads/<session>.jsonl, or names it with other values
  missing: 7, // no head or no receipt
});

/**
 * Check one countersigned session. notaryKeyId is required. operatorKeyId, when given, must be the key of every head,
 * and keys/<operatorKeyId>.pub must be trusted and hold the same key as each head's public_key.
 * Every head is checked (signature, and that the chain holds the head's hash at the head's seq). Every receipt is checked
 * (signature by the notary key, and that it names one of those heads exactly).
 * Returns { code, ok, failures: [{ code, message }], passed: [string], notes: [string], covered }.
 * covered is the highest seq named by a valid receipt, or null.
 */
export function checkSession({ session, notaryKeyId, operatorKeyId = null, home = witnessHome() }) {
  const failures = [];
  const passed = [];
  const notes = [];
  const fail = (code, message) => failures.push({ code, message });
  const done = (covered = null) => ({ code: failures.length ? failures[0].code : CHECK_EXIT.ok, ok: failures.length === 0, failures, passed, notes, covered });

  if (!validSession(session)) { fail(CHECK_EXIT.error, `invalid session id ${JSON.stringify(session ?? null)}`); return done(); }
  if (typeof notaryKeyId !== "string" || !KEY_ID_PATTERN.test(notaryKeyId)) { fail(CHECK_EXIT.error, "--notary <key_id> is required (k_ and 8 hex characters)"); return done(); }
  if (operatorKeyId !== null && !KEY_ID_PATTERN.test(String(operatorKeyId))) { fail(CHECK_EXIT.error, "--operator must be a key_id (k_ and 8 hex characters)"); return done(); }

  // 1. The session chain.
  const chain = readSessionChain(session, home);
  if (chain.missing || chain.parse) { fail(CHECK_EXIT.error, chain.problem); return done(); }
  const records = chain.records;
  if (chain.problem) fail(CHECK_EXIT.chain, `chain ${session}: ${chain.problem}`);
  else passed.push(`chain ${session}: ${records.length} records intact`);

  // 2. The heads.
  const heads = readHeads(session, home);
  if (heads.problem) { fail(CHECK_EXIT.error, `heads/${session}.jsonl: ${heads.problem}`); return done(); }
  if (heads.heads.length === 0) { fail(CHECK_EXIT.missing, `no head in heads/${session}.jsonl`); return done(); }
  let operatorPublic = null;
  if (operatorKeyId !== null) {
    const trust = trustedKey(operatorKeyId, home);
    if (trust.problem) fail(CHECK_EXIT.headSignature, `--operator ${operatorKeyId}: ${trust.problem}`);
    else operatorPublic = createPublicKey(trust.pem).export({ type: "spki", format: "der" }).toString("base64");
  }
  const goodHeads = new Map();
  heads.heads.forEach((head, i) => {
    const label = `head ${i + 1} of heads/${session}.jsonl`;
    const bad = checkHead(head);
    if (bad) { fail(CHECK_EXIT.headSignature, `${label}: ${bad.reason}`); return; }
    if (operatorKeyId !== null) {
      if (head.key_id !== operatorKeyId) { fail(CHECK_EXIT.headSignature, `${label}: signed by ${head.key_id}, not the --operator key ${operatorKeyId}`); return; }
      if (operatorPublic !== null && head.public_key !== operatorPublic) { fail(CHECK_EXIT.headSignature, `${label}: its public_key is not the key in keys/${operatorKeyId}.pub`); return; }
      if (operatorPublic === null) return;
    }
    if (head.session !== session) { fail(CHECK_EXIT.head, `${label}: names session ${JSON.stringify(head.session)}, not ${session}`); return; }
    const record = records[head.seq];
    if (!record) { fail(CHECK_EXIT.head, `${label}: seq ${head.seq} is past the end of the chain (${records.length} records)`); return; }
    if (record.hash !== head.hash) { fail(CHECK_EXIT.head, `${label}: the record at seq ${head.seq} has hash ${String(record.hash).slice(0, 12)}, the head says ${head.hash.slice(0, 12)}`); return; }
    goodHeads.set(headDigest(head), head);
  });

  // 3. The notary key and the receipts.
  const notaryTrust = trustedKey(notaryKeyId, home);
  if (notaryTrust.problem) { fail(CHECK_EXIT.receiptSignature, `--notary ${notaryKeyId}: ${notaryTrust.problem}`); return done(); }
  const receipts = readReceipts(session, home);
  if (receipts.problem) { fail(CHECK_EXIT.error, `receipts/${session}.jsonl: ${receipts.problem}`); return done(); }
  if (receipts.receipts.length === 0) { fail(CHECK_EXIT.missing, `no receipt in receipts/${session}.jsonl`); return done(); }
  const allHeads = new Map(heads.heads.map((h) => { try { return [headDigest(h), h]; } catch { return [null, h]; } }));
  let covered = null;
  receipts.receipts.forEach((receipt, i) => {
    const label = `receipt ${i + 1} of receipts/${session}.jsonl`;
    const bad = checkReceipt(receipt, { notaryKeyId, home });
    if (bad) { fail(CHECK_EXIT.receiptSignature, `${label}: ${bad.reason}`); return; }
    const head = allHeads.get(receipt.head.sha256);
    if (!head) { fail(CHECK_EXIT.receiptHead, `${label}: names head ${receipt.head.sha256.slice(0, 12)} (session ${receipt.head.session}, seq ${receipt.head.seq}), which is not in heads/${session}.jsonl`); return; }
    const mismatch = receiptMatches(receipt, head);
    if (mismatch) { fail(CHECK_EXIT.receiptHead, `${label}: ${mismatch}`); return; }
    // A receipt for a head that failed its own checks adds no coverage; that head's failure is already listed.
    if (!goodHeads.has(receipt.head.sha256)) return;
    passed.push(`${label}: seq ${head.seq} hash ${head.hash.slice(0, 12)} sealed by ${head.key_id} at ${head.ts}, countersigned by ${receipt.signer.key_id} at ${receipt.ts} (notary seq ${receipt.seq})`);
    covered = covered === null ? head.seq : Math.max(covered, head.seq);
  });
  if (operatorKeyId === null && goodHeads.size) notes.push(`operator key taken from the heads: ${[...new Set([...goodHeads.values()].map((h) => h.key_id))].join(", ")}. Pass --operator <key_id> to require a key you hold.`);
  if (covered !== null && records.length - 1 > covered) notes.push(`records ${covered + 1} to ${records.length - 1} are after the last countersigned head and are not covered`);
  return done(covered);
}
