# Field map: IETF draft-ietf-wimse-aims-00, Section 11

Section 11 of draft-ietf-wimse-aims-00 lists what an audit event MUST contain, and says audit records MUST be tamper-evident. This page maps each item to the Witness field that holds it, or states that Witness does not record it. "Session record" means a record in `log/<session>.jsonl` ([SPEC.md](../SPEC.md), format v0.1). Fields from [SPEC-0.2.md](../SPEC-0.2.md) and [SPEC-0.4.md](../SPEC-0.4.md) are named with their file.

The draft is an Internet-Draft, version 00. This map follows that version only.

| Section 11 item | Witness field | Status |
|---|---|---|
| The authenticated agent identifier | none | Not recorded |
| The delegated subject (user or system), when present | `principal` on `session_start` and `tool_call` | Recorded as declared, not authenticated |
| The resource or tool being accessed | `tool`, `server` on `tool_call` | Recorded |
| The action requested and the authorization decision | action: `tool`, `args_sha256`, `args_bytes` on `tool_call`. decision: none in the recorder | Action recorded as a digest. Decision not recorded by the recorder |
| A timestamp and transaction or request correlation identifier | `ts`, `session`, `seq`, `rpc_id`, `call_seq` | Recorded |
| The posture assessment or risk state | none | Not recorded |
| Remediation or revocation events and their cause | none | Not recorded |
| Audit records MUST be tamper-evident | `prev`, `hash`; heads and receipts (SPEC-0.4) | Tamper-evident, with the limits below |

## Item by item

**The authenticated agent identifier.** Witness does not record an authenticated agent identifier. The closest field is `actor` (`{ client, version, protocol }`), copied from the MCP `initialize` request. The client declares it, and nothing checks it. The `key_id` on a v0.4 head names the key that sealed the log, not the agent.

**The delegated subject, when present.** `principal` (`{ as, source, verified }`) holds the subject the operator declared with `--as` or `WITNESS_AS`. `source` is `flag`, `env` or `none`. `verified` is always `false`. Witness does not record an authenticated or delegated subject, and does not record a delegation chain.

**The resource or tool being accessed.** `tool_call.tool` is the tool name. `server.name` is the server name, from `--name`, the command basename (stdio) or the upstream host name (HTTP). `server.cmd_sha256` (stdio) is a digest of the full command line. `server.upstream_sha256` (HTTP) is a digest of the upstream origin and path. The tool's own resource arguments (for example a file path) are digested in `args_sha256`, and appear in plaintext only in `args_summary`, only for keys the operator allow-lists.

**The action requested and the authorization decision.** The action is `tool_call`: `tool`, `args_sha256` and `args_bytes`, with `rpc_id`. Arguments are digested, never stored. The recorder does not authorize calls, so its session records hold no authorization decision. `tool_result.outcome.status` (`ok`, `error`, `unknown`) is what the server answered, not a decision. SPEC-0.2 defines `grant.decision` (`run`, `hold`, `refuse`), `override.answer` and `refusal` for session chains, but they are written by the council mod, which is not in this package; the recorder never writes them.

**A timestamp and transaction or request correlation identifier.** Every record has `ts` (ISO-8601 UTC, millisecond precision, the recorder's clock), `session` and `seq`. `tool_call.rpc_id` is the JSON-RPC id. `tool_result.call_seq` is the `seq` of the call it answers. A v0.4 receipt adds the notary's `ts` for a head, which is a second clock for every record up to that head's `seq`. Witness does not record a trace or request id from outside the MCP frame.

**The posture assessment or risk state.** Witness does not record a posture assessment or a risk state at the time of a call. A `judge` record (SPEC-0.2 section 4, `verdict` and `findings`) is a review written after the session, by a model that reads the records. It is not a posture assessment at access time. A `vote` (`p_unsafe`) is written by the council mod, not by this package.

**Remediation or revocation events and their cause.** Witness does not record remediation or revocation events. It has no revocation of agent credentials, and no key revocation (SPEC-0.4 section 6). A `refusal` record (SPEC-0.2, written by the council mod) records that one call was refused and why. It is not a revocation.

**Tamper-evident.** Every record carries `prev` and `hash = sha256(canonical(record) + prev)`, so an edit breaks the chain at that record and a deletion breaks it at the next. A v0.4 head signs the last record's `hash`, and a notary receipt signs the head's digest in a chain the operator does not hold. When the checker holds a receipt it got independently of the operator, or runs `witness check --notary-log` on a copy of the notary log, check detects an edit before the sealed `seq` even when the whole chain was rebuilt (exit 3, 6 or 8). With only the files the operator hands over, a log that the operator rewrote, sealed and countersigned again passes (SPEC-0.4 section 6). Limits: a truncated tail is not detected without a head or a checkpoint; records after the last countersigned head are covered by no receipt; and a notary that colludes with the operator proves nothing. See [THREAT_MODEL.md](THREAT_MODEL.md).
