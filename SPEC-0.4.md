# Witness format v0.4: countersigned heads

Status: **draft, Oct 23 2026**. Extends [SPEC.md](SPEC.md) (format v0.1) and [SPEC-0.2.md](SPEC-0.2.md). Session records do not change: they still carry `"v": "0.1"`, and nothing on this page is written into a session file. Head statements and receipts carry `"v": "0.4"`. `canonical()` and the record `hash` are as defined in SPEC.md.

Thesis: a session chain detects edits but not a rewrite by whoever holds the files. A signed head names the last record of a chain. A notary, run by another party with its own key, receipts the head in its own chain. An outside party can then check a log against a receipt it did not have to trust the operator for.

## 1. Files

| File | Path under `$WITNESS_HOME` | Writer | Holds |
|---|---|---|---|
| heads | `heads/<session>.jsonl` | `witness seal`, `witness countersign` | head statements for one session, append-only |
| receipts | `receipts/<session>.jsonl` | `witness countersign` | receipts for one session, as the notary returned them, append-only |
| notary log | `notary/log.jsonl` | `witness notary serve` (on the notary's home) | one hash-chained, signed receipt per accepted head |

Directories are 0700 and files 0600. Every file on this page is read with the strict parser of SPEC-0.2 section 5: valid UTF-8, one JSON object per line, a blank line is a bad line, and the empty element after a final newline is not a line. A writer refuses to append to a non-empty file that does not end with a newline.

## 2. Head statement

One line of `heads/<session>.jsonl`. It has exactly these fields:

| Field | Type | Meaning |
|---|---|---|
| `v` | string | `"0.4"` |
| `type` | string | `"head"` |
| `session` | string | the session id, from the log file name, `[A-Za-z0-9_.-]{1,128}` |
| `seq` | integer | `seq` of the last record of `log/<session>.jsonl` when sealed |
| `hash` | string | `hash` of that record, 64 lowercase hex |
| `records` | integer | the number of records in the chain when sealed; always `seq + 1` |
| `ts` | string | ISO-8601 UTC, the operator's clock |
| `key_id` | string | the operator key, `k_` and 8 hex (SPEC-0.2 section 2) |
| `alg` | string | `"ed25519"` |
| `public_key` | string | the operator public key, base64 of its SPKI DER, canonical base64 |
| `sig` | string | base64 ed25519 signature over the UTF-8 bytes of `canonical(statement without sig)` |

A head holds when: it has exactly these fields with these types; `records` equals `seq + 1`; `public_key` decodes to an ed25519 key; `key_id` equals `k_` plus the first 8 hex of sha256 of that key's SPKI DER; and `sig` verifies over `canonical` of every other field with that key. The head carries its own key, so it can be checked with nothing else. Whether that key belongs to the operator is a separate question (section 4, `--operator`).

The head's digest is `sha256(canonical(head))` with `sig` included. A receipt names its head by this digest.

`witness seal` writes a head only for a chain that verifies and whose every `seq` equals its position. A session may be sealed again as it grows; each seal appends one head. A seal of a chain whose last head already names the same `seq`, `hash` and `key_id` appends nothing.

The head signature is over the canonical statement, not over a record hash: this differs from the `signer` block of SPEC-0.2, which signs a record's 32-byte `hash`.

## 3. Receipt and notary log

A notary is a separate process, run by a party other than the operator, with its own key (`witness keygen` on its own home). It receives a head, checks it on its own (section 2), and appends one receipt to `notary/log.jsonl`. The receipt is the notary log record. It has exactly these fields:

| Field | Type | Meaning |
|---|---|---|
| `v` | string | `"0.4"` |
| `seq` | integer | the receipt's position in the notary log |
| `ts` | string | ISO-8601 UTC, the notary's clock when it appended the receipt |
| `session` | string | `"notary"` |
| `event` | string | `"receipt"` |
| `head` | object | `{ sha256, session, seq, hash, key_id }`: the head's digest, and its `session`, `seq`, `hash` and `key_id` |
| `prev` | string | `hash` of the previous receipt in the notary log, or `"GENESIS"` |
| `hash` | string | `sha256(canonical(receipt without hash and signer) + prev)`, as in SPEC.md |
| `signer` | object | `{ key_id, alg: "ed25519", sig }` as in SPEC-0.2 section 2: `sig` signs the raw 32 bytes of `hash` |

The notary log verifies when: it is one chain; `seq` equals the position; every record has exactly the fields above; every record has a `signer`, and every signer is the same `key_id`; `keys/<key_id>.pub` exists, is ed25519 and hashes to `key_id`; and every signature is valid. A record without a signer fails, because the hash does not cover `signer`.

The notary does not need the operator's key in its `keys/`. It attests only that a head, valid under the key it carries, reached the notary at `ts` and holds position `seq` in the notary log. Every accepted POST appends a receipt, also for a head it has seen before.

## 4. Offline check

`witness check <session> --notary <key_id>` reads only `log/<session>.jsonl`, `heads/<session>.jsonl`, `receipts/<session>.jsonl` and `keys/*.pub` under `$WITNESS_HOME`. It writes nothing and opens no socket. An outside party copies those files into an empty directory, adds the notary's `.pub` (and optionally the operator's) to `keys/`, and sets `WITNESS_HOME` to it.

The checks, in order:

1. The session chain verifies (SPEC.md), and every `seq` equals its position.
2. Every head holds (section 2). With `--operator <key_id>`, every head's `key_id` equals it and its `public_key` is the key in the trusted `keys/<key_id>.pub`.
3. Every head names this session, and the record at position `head.seq` exists and has `hash` equal to `head.hash`. The chain may continue past a head.
4. `keys/<notary key_id>.pub` is trusted: present, ed25519, hashing to the key_id.
5. Every receipt has the fields of section 3, is signed by the `--notary` key, its `hash` recomputes, and its signature is valid.
6. Every receipt's `head.sha256` is the digest of a head in `heads/<session>.jsonl`, and its `session`, `seq`, `hash` and `key_id` equal that head's.
7. There is at least one head and at least one receipt.

Every failure is reported on its own line. The exit code is that of the first failure in the order above: every head's signature check (step 2) runs before any head is matched to the chain (step 3), and every receipt's signature check (step 5) before any receipt is matched to a head (step 6). The order of lines in the files does not change the code.

| Exit | Meaning |
|---|---|
| 0 | every check holds |
| 1 | bad arguments, a missing log file, a read error, or a line of the heads or receipts file that does not parse |
| 2 | the session chain is broken, also by a blank, unparseable or non-UTF-8 line |
| 3 | a head does not match the chain: another hash at its `seq`, its `seq` past the end, or another session |
| 4 | a head is malformed, its `key_id` does not match its `public_key`, its signature fails, or it is not the `--operator` key |
| 5 | a receipt is malformed or not signed by the `--notary` key, that key is not trusted, or the receipt's hash or signature fails |
| 6 | a receipt names no head in `heads/<session>.jsonl`, or names it with other values |
| 7 | no head, or no receipt |

The output names the highest `seq` covered by a valid receipt, and the records after it, which no receipt covers.

## 5. CLI contracts

```
witness seal [<session>|--all] --key <key_id>
    For each session: verify log/<session>.jsonl; a broken chain is not sealed (FAIL, exit 3).
    Append one head to heads/<session>.jsonl unless the last head there already names the same seq, hash and key_id.
    keys/<key_id>.key must hold an ed25519 key that hashes to key_id. No .pub is needed. The private key is never printed.
    One line per session: SEALED, SAME (already sealed) or FAIL. Exit 0 ok, 1 error, 3 broken chain or heads file.

witness notary serve --key <key_id> [--host 127.0.0.1] [--port 7481] [--any-interface]
    Bind only to --host, with the host rules of feed serve (SPEC-0.2 section 6): an empty, whitespace or non-string host
    and every spelling of an every-interface address exit 1, unless --any-interface is given for the latter.
    keys/<key_id>.key and keys/<key_id>.pub must both belong to key_id. notary/log.jsonl must verify (section 3)
    and end with a newline, or serve exits 3 and does not listen (1 for a read error). Print {"listen": "<url>", "key_id", "log"}.
    POST /receipt   body: one head statement as JSON.
        400  the body is not UTF-8 JSON, or not a head statement (shape)
        413  the body is larger than 64 KiB; a declared Content-Length over the cap is refused before the body is read
        422  key_id does not match public_key, or the signature does not verify
        200  the receipt, one JSON line, application/json. It is appended to notary/log.jsonl before the reply.
        500  the log cannot be written, or no longer verifies; every later request then gets 500
    Another method on /receipt: 405 with Allow: POST. Every other path: 404. A 404, 405, 413 or 503 closes its connection.
    At most 8 requests at once; another gets 503 with Retry-After: 1. A socket with no traffic for 30 seconds is
    destroyed, and a request must arrive in 30 seconds. Appends hold the lock notary/log.jsonl.lock.
    Before each append, the last line on disk must be the last line this process knows; if not, the whole log is
    verified again.

witness notary verify [--key <key_id>]
    Walk notary/log.jsonl (section 3). With --key, every signer must be that key.
    Exit 0 intact, 1 read error, 3 broken (also for invalid UTF-8 or a blank or unparseable line).

witness countersign <url> [<session>|--all] --key <key_id> [--notary <key_id>]
    url is the notary's /receipt endpoint. userinfo and fragment are removed before the request.
    With --notary, keys/<key_id>.pub must be trusted before anything is sent (else exit 1).
    For each session: seal as above. If a stored receipt in receipts/<session>.jsonl names the last head and passes
    every check below that a new receipt must pass, with the --notary key when given, send nothing (SAME). A stored
    receipt that fails, or is signed by another key than --notary, does not count. Without --notary, any stored receipt
    that passes counts, so pass --notary to countersign with a second notary.
    Otherwise send exactly one POST with the head, follow no redirect, read at most 64 KiB in 30 seconds.
    The receipt must have the fields of section 3, name the sent head exactly, and its hash must recompute.
    Its signature is checked when --notary is given, or when keys/ holds a trusted .pub for its signer; a receipt
    that fails is not stored (exit 3). With neither, the receipt is stored and reported as unverified.
    Append the receipt to receipts/<session>.jsonl. One line per session: SIGNED, SAME or FAIL.
    Exit 0 ok, 1 error (network, status other than 200, key), 3 broken chain, broken file or bad receipt.

witness check <session> --notary <key_id> [--operator <key_id>] [--json]
    Section 4. Lines: OK for each check that holds, FAIL for each failure, NOTE for the operator key source and
    for records after the last countersigned head. --json prints one object with code, failures, passed, notes, covered.
```

## 6. What v0.4 does not claim

- **No completeness.** A receipt covers the records up to the sealed `seq` of one wrapped session. It says nothing about calls that bypassed Witness, servers that were not wrapped, or sessions that were never sealed.
- **No truth of outcomes.** A receipt proves that a chain with this head existed by the notary's `ts`. It does not prove that any record describes what really happened.
- **Nothing after the sealed seq.** Records appended after the last countersigned head are covered by no receipt. A tail truncated back to the sealed seq is not detected.
- **A colluding notary proves nothing.** A notary that shares keys or interests with the operator can issue receipts at any time with any `ts`. The receipt is worth exactly the independence of the notary.
- **No trusted time.** `ts` is the notary's clock. There is no timestamp authority and no public transparency log. A notary can show different logs to different parties, and a party that holds only its own receipts cannot tell.
- **No proof that a rewrite did not happen later.** An operator who rewrites a log can seal and countersign the rewrite. The new receipt has a later notary `ts` and `seq`, and the notary log still holds the receipt for the original head. A check against only the rewritten files passes; the rewrite shows only against an earlier receipt or the notary log.
- **No operator identity.** `key_id` names a key, not a person or a machine. Without `--operator`, check uses the key the head carries. The principal in session records stays `verified: false`.
- **No key revocation or rotation.**
