# Changelog

## 0.4.0 (2026-10-23)

A countersigned logbook. See [SPEC-0.4.md](SPEC-0.4.md).

- **`witness seal`.** Signs the head of a session chain (session, last `seq` and `hash`, record count, time, `key_id`, public key) with an ed25519 key from `keys/`, into `heads/<session>.jsonl`. A broken chain is not sealed.
- **`witness notary serve` and `witness notary verify`.** A notary, run by another party with its own key, checks a posted head's signature and `key_id`, appends a signed receipt to its own chain `notary/log.jsonl`, and returns it. Host rules, body cap, concurrency cap and stall limit as `feed serve`. `notary verify` walks the chain.
- **`witness countersign <url>`.** Seals when needed, sends each new head, checks the receipt and stores it in `receipts/<session>.jsonl`.
- **`witness check <session> --notary <key_id>`.** Offline verifier for an outside party: chain intact, head at its `seq`, head signature, receipt signature, receipt names the head. Exit codes 0 to 7, one per kind of failure.
- **`docs/FIELD-MAP.md`.** Maps record fields to the audit-event list in IETF draft-ietf-wimse-aims-00 Section 11, and names the items Witness does not record.
- `readFeedFile` also returns the exit code of its problem, so a notary log line that does not parse counts as a broken log.
- Session record format unchanged: still `v: "0.1"`. Heads and receipts carry `v: "0.4"`.

## 0.3.0 — 2026-09-13

Witness is now just the recorder.

- **Split.** The operator UI, local-source adapters, bounded control service, evidence-bundle export, and the product/pilot documents moved out of this repository. What remains is the MCP proxy (stdio and HTTP/SSE), the v0.1 record format, and the CLI (`wrap`, `unwrap`, `verify`, `tail`, `sessions`, `query`, `report`, `anchor`).
- **Zero dependencies.** `npm install` installs nothing. `npm test` runs in seconds with no build step.
- **Publishable.** Package renamed to `@darkvectorcognition.ai/witness`, `private` removed, `exports` map added so `lib/` modules can be imported by other tools.
- **DCO.** Contributions require a `Signed-off-by` line (see `CONTRIBUTING.md`).
- Docs rewritten to describe only what this package does. `THREAT_MODEL.md` and `PRIVACY.md` now cover the recorder, not the former vertical slice.
- Record format unchanged: still `v: "0.1"`. Records written by 0.2.0 verify with 0.3.0.

## 0.2.0 — 2026-09-12

- MCP stdio proxy recorder with the v0.1 record schema; `verify`, `tail`, `sessions`.
- `wrap` / `unwrap` for `.mcp.json`, `~/.claude.json`, Cursor, and Claude Desktop configs.
- `query`, `report`, `anchor` (`--git`).
- HTTP / SSE transport: `witness http --upstream <url>`.
- `verify` accepts concatenated exports (one chain per session within a file).
