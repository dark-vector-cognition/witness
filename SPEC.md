# Witness record format — v0.1

Status: **stable for v0.1**. Implementable without this repository's code. Changes bump `v`.

## Storage

One append-only JSONL file per proxied session: `$WITNESS_HOME/log/<session>.jsonl` (default `~/.witness/log/`). One JSON object per line. Files are created `0600`, the directory `0700`. Nothing is ever rewritten; a rewrite is detectable.

## Envelope (every record)

| Field | Type | Meaning |
|---|---|---|
| `v` | string | Schema version, `"0.1"` |
| `seq` | integer | 0-based position in this session's chain |
| `ts` | string | ISO-8601 UTC, millisecond precision |
| `session` | string | `s_` + 8 hex chars, unique per proxy process |
| `event` | string | One of the event types below |
| `prev` | string | `hash` of the previous record, or `"GENESIS"` for `seq` 0 |
| `hash` | string | `sha256( canonical(record without hash) + prev )`, hex |

`canonical()` = JSON with object keys sorted lexicographically at every depth, no whitespace, arrays in order. Any implementation that sorts keys and serialises with `JSON.stringify` semantics reproduces the hash.

## Event types

| `event` | Emitted when | Extra fields |
|---|---|---|
| `session_start` | Proxy spawns the server | `actor`, `principal`, `server`, `pid` |
| `session_client` | Client sends `initialize` | `actor` (now populated from `clientInfo`) |
| `tool_call` | Client sends `tools/call` | `rpc_id`, `tool`, `args_sha256`, `args_bytes`, `args_summary?`, `actor`, `principal`, `server` |
| `tool_result` | Server answers that `rpc_id` — or never does | `rpc_id`, `tool`, `call_seq`, `outcome` |
| `notification` | Client sends a JSON-RPC notification | `direction`, `method` |
| `raw` | A non-JSON line passes in either direction | `direction`, `line_sha256`, `bytes` |
| `error` | The server process could not be started | `message` |
| `session_end` | Server exits or client closes stdin | `exit {code, signal}`, `counts {calls, ok, error, raw}`, `ms`, `unresolved` |

### Sub-objects

- `actor`: `{ client, version, protocol }` — from the MCP `initialize` request. `"unknown"` until seen.
- `principal`: `{ as, source, verified }` — **declared, not proven** in v0.1. `source` is `flag` (`--as`), `env` (`WITNESS_AS`), or `none`. `verified` is always `false` in v0.1; a verifying implementation must set it `true` only with cryptographic evidence and must say how.
- `server`: `{ name, cmd_sha256 }` — `--name` or the command basename; digest of the full command line so a substituted binary is visible.
- `outcome`: `{ status, ms, result_sha256?, result_bytes?, code?, reason? }` — `status` ∈ `ok` (result without `isError`), `error` (JSON-RPC `error` or `result.isError === true`), `unknown` (server exited before answering).

## Privacy rule

Arguments and results are **digested, never stored**: `args_sha256` / `result_sha256` are the SHA-256 of the canonical JSON. `args_summary` exists only when the operator allow-lists keys with `--allow`, and never for keys matching `/token|secret|password|authorization|cookie|api[_-]?key|credential/i`. String values in a summary are truncated to 120 characters. Server `stderr` is passed through and never recorded.

## Verification

Walk records in file order; for each, assert `prev` equals the previous `hash` (or `GENESIS`), recompute the hash, compare. The first failing record is the tamper point. `witness verify` implements this and exits non-zero on any broken chain.

## What v0.1 does not claim

No proven identity, no signing key, no external timestamp, no enforcement. A chain proves *internal* consistency and detects edits; anchoring the chain head elsewhere (git commit, timestamp authority) is how it gains a third-party clock — v0.2.
