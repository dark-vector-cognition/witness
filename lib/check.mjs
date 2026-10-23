// witness check: the offline verifier for a countersigned session. Format v0.4, see SPEC-0.4.md section 4.
// It reads only log/<session>.jsonl, heads/<session>.jsonl, receipts/<session>.jsonl and keys/*.pub under one home,
// so an outside party can run it on copies of those files. It writes nothing and opens no socket.
import { checkHead, headDigest, readHeads, readSessionChain, validSession } from "./heads.mjs";
import { fingerprintOf, keySpec, pinnedKey } from "./keys.mjs";
import { checkReceipt, readReceipts, receiptMatches } from "./notary.mjs";
import { witnessHome } from "./session-log.mjs";

/** Exit codes of witness check. With several failures the code is the one of the first failure, in the order the checks run. */
export const CHECK_EXIT = Object.freeze({
  ok: 0,
  error: 1, // bad arguments, a missing log file, a read error, or a heads or receipts line that does not parse
  chain: 2, // the session chain is broken, also by a blank, unparseable or non-UTF-8 line
  head: 3, // a head does not match the chain (wrong hash at its seq, seq past the end, another session)
  headSignature: 4, // a head is malformed, its key_id does not match its public_key, its signature fails, or it is not the --operator key
  receiptSignature: 5, // a receipt is malformed, not signed by the --notary key, the key is not trusted, or hash or signature fails
  receiptHead: 6, // a receipt does not name a head in heads/<session>.jsonl, or names it with other values
  missing: 7, // no head or no receipt
});

/**
 * Check one countersigned session. notaryKeyId is required. notaryKeyId and operatorKeyId are each a full fingerprint
 * (64 hex, which pins the key) or a key_id (a 32-bit shorthand; a NOTE says so). operatorKeyId, when given, must be the
 * key of every head, and the trusted keys/<key_id>.pub must hold the same key as each head's public_key.
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
  if (!keySpec(notaryKeyId)) { fail(CHECK_EXIT.error, "--notary is required: a fingerprint (64 hex characters) or a key_id (k_ and 8 hex characters)"); return done(); }
  if (operatorKeyId !== null && !keySpec(operatorKeyId)) { fail(CHECK_EXIT.error, "--operator must be a fingerprint (64 hex characters) or a key_id (k_ and 8 hex characters)"); return done(); }
  const shortNote = (flag, key) => notes.push(`${flag} ${key.keyId} is a 32-bit key_id, and any key with that prefix is accepted. Pin the key: ${flag} ${key.fingerprint ?? "<fingerprint>"}`);

  // 1. The session chain. A blank, unparseable or non-UTF-8 line is a broken chain (exit 2); only a read error is exit 1.
  const chain = readSessionChain(session, home);
  if (chain.missing || chain.readError) { fail(CHECK_EXIT.error, chain.problem); return done(); }
  const records = chain.records;
  const chainReadable = !chain.parse;
  if (chain.problem) fail(CHECK_EXIT.chain, `chain ${session}: ${chain.problem}`);
  else passed.push(`chain ${session}: ${records.length} records intact`);

  // 2. The heads, in two passes so the exit code follows SPEC-0.4 section 4: every signature check, then every chain match.
  const heads = readHeads(session, home);
  if (heads.problem) { fail(CHECK_EXIT.error, `heads/${session}.jsonl: ${heads.problem}`); return done(); }
  if (heads.heads.length === 0) { fail(CHECK_EXIT.missing, `no head in heads/${session}.jsonl`); return done(); }
  const operator = operatorKeyId === null ? null : pinnedKey(operatorKeyId, home);
  if (operator?.problem) fail(CHECK_EXIT.headSignature, `--operator ${operatorKeyId}: ${operator.problem}`);
  else if (operator) {
    passed.push(`operator key ${operator.keyId} fingerprint ${operator.fingerprint}`);
    if (operator.short) shortNote("--operator", operator);
  }
  const headFingerprint = (head) => fingerprintOf({ key: Buffer.from(head.public_key, "base64"), format: "der", type: "spki" });
  const label = (i) => `head ${i + 1} of heads/${session}.jsonl`;
  const signedHeads = [];
  heads.heads.forEach((head, i) => {
    const bad = checkHead(head);
    if (bad) { fail(CHECK_EXIT.headSignature, `${label(i)}: ${bad.reason}`); return; }
    if (operator) {
      if (head.key_id !== operator.keyId) { fail(CHECK_EXIT.headSignature, `${label(i)}: signed by ${head.key_id}, not the --operator key ${operator.keyId}`); return; }
      if (operator.problem) return;
      if (headFingerprint(head) !== operator.fingerprint) { fail(CHECK_EXIT.headSignature, `${label(i)}: its public_key has fingerprint ${headFingerprint(head)}, not the --operator fingerprint ${operator.fingerprint}`); return; }
    }
    signedHeads.push([i, head]);
  });
  const goodHeads = new Map();
  for (const [i, head] of signedHeads) {
    if (head.session !== session) { fail(CHECK_EXIT.head, `${label(i)}: names session ${JSON.stringify(head.session)}, not ${session}`); continue; }
    // A chain that does not parse has no records to match; its exit 2 is already listed.
    if (!chainReadable) continue;
    const record = records[head.seq];
    if (!record) { fail(CHECK_EXIT.head, `${label(i)}: seq ${head.seq} is past the end of the chain (${records.length} records)`); continue; }
    if (record.hash !== head.hash) { fail(CHECK_EXIT.head, `${label(i)}: the record at seq ${head.seq} has hash ${String(record.hash).slice(0, 12)}, the head says ${head.hash.slice(0, 12)}`); continue; }
    goodHeads.set(headDigest(head), head);
  }

  // 3. The notary key and the receipts.
  const notary = pinnedKey(notaryKeyId, home);
  if (notary.problem) { fail(CHECK_EXIT.receiptSignature, `--notary ${notaryKeyId}: ${notary.problem}`); return done(); }
  passed.push(`notary key ${notary.keyId} fingerprint ${notary.fingerprint}`);
  if (notary.short) shortNote("--notary", notary);
  const receipts = readReceipts(session, home);
  if (receipts.problem) { fail(CHECK_EXIT.error, `receipts/${session}.jsonl: ${receipts.problem}`); return done(); }
  if (receipts.receipts.length === 0) { fail(CHECK_EXIT.missing, `no receipt in receipts/${session}.jsonl`); return done(); }
  const allHeads = new Map(heads.heads.map((h) => { try { return [headDigest(h), h]; } catch { return [null, h]; } }));
  // Two passes again: every receipt signature, then every receipt against the heads.
  const rlabel = (i) => `receipt ${i + 1} of receipts/${session}.jsonl`;
  const signedReceipts = [];
  receipts.receipts.forEach((receipt, i) => {
    const bad = checkReceipt(receipt, { notaryKeyId: notary.keyId, pem: notary.pem, home });
    if (bad) fail(CHECK_EXIT.receiptSignature, `${rlabel(i)}: ${bad.reason}`);
    else signedReceipts.push([i, receipt]);
  });
  let covered = null;
  for (const [i, receipt] of signedReceipts) {
    const head = allHeads.get(receipt.head.sha256);
    if (!head) { fail(CHECK_EXIT.receiptHead, `${rlabel(i)}: names head ${receipt.head.sha256.slice(0, 12)} (session ${receipt.head.session}, seq ${receipt.head.seq}), which is not in heads/${session}.jsonl`); continue; }
    const mismatch = receiptMatches(receipt, head);
    if (mismatch) { fail(CHECK_EXIT.receiptHead, `${rlabel(i)}: ${mismatch}`); continue; }
    // A receipt for a head that failed its own checks adds no coverage; that head's failure is already listed.
    if (!goodHeads.has(receipt.head.sha256)) continue;
    passed.push(`${rlabel(i)}: seq ${head.seq} hash ${head.hash.slice(0, 12)} sealed by ${head.key_id} at ${head.ts}, countersigned by ${receipt.signer.key_id} at ${receipt.ts} (notary seq ${receipt.seq})`);
    covered = covered === null ? head.seq : Math.max(covered, head.seq);
  }
  if (operatorKeyId === null && goodHeads.size) notes.push(`operator key taken from the heads: ${[...new Set([...goodHeads.values()].map((h) => `${h.key_id} fingerprint ${headFingerprint(h)}`))].join(", ")}. Pass --operator <fingerprint> to require a key you hold.`);
  if (covered !== null && records.length - 1 > covered) notes.push(`records ${covered + 1} to ${records.length - 1} are after the last countersigned head and are not covered`);
  return done(covered);
}
