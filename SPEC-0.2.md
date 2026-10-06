# Witness record format v0.2: readers of the stream

Status: **draft, Oct 6 2026**. Extends [SPEC.md](SPEC.md) (format v0.1). Every v0.1 rule still holds: one append-only JSONL chain per file, `canonical()` and `hash` as defined there, arguments and results digested and never stored. Records that use anything on this page carry `"v": "0.2"`. A v0.1 verifier rejects nothing here; it only sees unknown event types.

Thesis: one stream, many readers. Every reader writes its findings as new records. No reader edits a record. Ticket: LOCAL-543.

## 1. Chains

| Chain | Path under `$WITNESS_HOME` | Writer | Holds |
|---|---|---|---|
| session | `log/<session>.jsonl` | the recorder (proxy or the witness-recorder mod) | v0.1 events plus `vote`, `grant`, `override`, `refusal` |
| judgment | `judge/<session>.jsonl` | `witness judge` and `witness score` | `judge`, `outcome_label`, `score`, `rotation` |
| feed | `feed/refusals.jsonl` | the council mod, through `witness feed` | `feed` |

Each chain is independent: `seq` starts at 0, `prev` starts at `GENESIS`. A judgment chain names the session chain it reads through `subject`. A reader never opens a session file for writing.

## 2. Signing (optional in v0.2)

Any record may carry `signer`:

```json
"signer": { "key_id": "k_3f2a9c1e", "alg": "ed25519", "sig": "<base64 of ed25519(hash)>" }
```

`sig` signs the record's `hash`, so the hash is computed first, with `signer` absent, then `signer` is attached. Verification: recompute `hash` on the record without `signer`, then check `sig` against the public key for `key_id`. Keys live in `$WITNESS_HOME/keys/<key_id>.pub`. A record without `signer` is unsigned, not invalid. `principal.verified` stays `false` unless a signature covers the record.

## 3. Session chain additions

### `vote`

Emitted by the council mod before a held tool call runs. One record per judge.

| Field | Type | Meaning |
|---|---|---|
| `call_seq` | integer | `seq` of the `tool_call` this vote is about |
| `rpc_id` | string or number | the call's JSON-RPC id |
| `judge` | object | `{ id, model, vendor, view }`. `view` is `full` (saw the text) or `metadata` (saw only tool, args digest, sizes, source) |
| `p_unsafe` | number | the judge's probability in [0, 1] that the call should not run as asked |
| `max_caps` | array of string | the largest capability set this judge allows. Vocabulary: `read`, `list`, `write`, `exec`, `net`, `money`, `delete`, `push` |
| `reason` | string | up to 240 characters, no raw tool arguments, no secrets |
| `ms` | integer | judge latency |

### `grant`

Emitted once per held call, after every vote.

| Field | Type | Meaning |
|---|---|---|
| `call_seq` | integer | as above |
| `requested` | array of string | capabilities the call needs |
| `granted` | array of string | the intersection of every `max_caps`, then intersected with `requested` |
| `decision` | string | `run` when `granted` equals `requested`; `hold` when a human must answer; `refuse` when any judge's `max_caps` excludes a requested capability and no appeal path exists |
| `votes` | array of integer | `seq` of each `vote` record counted |
| `veto` | string or null | `judge.id` of the strictest judge when `decision` is not `run` |

The grant is computed by the harness side of the mod, never by a judge.

### `override`

Emitted when a human answers a `hold`.

| Field | Type | Meaning |
|---|---|---|
| `call_seq` | integer | as above |
| `grant_seq` | integer | `seq` of the `grant` |
| `answer` | string | `proceed` or `cancel` |
| `by` | object | `{ as, source }` like `principal` |

### `refusal`

Emitted when a `grant` decides `refuse`, or a human answers `cancel`. This is the only record projected into the feed.

| Field | Type | Meaning |
|---|---|---|
| `call_seq` | integer | as above |
| `indicator` | object | `{ kind, sha256 }`. `kind` is `document`, `domain`, `arg_pattern` or `tool`. `sha256` digests the indicator; the raw value is never stored |
| `reason` | string | up to 240 characters |

## 4. Judgment chain

### `judge`

Written by `witness judge`. A fresh model instance with no session context reads one session chain and reports.

| Field | Type | Meaning |
|---|---|---|
| `subject` | object | `{ session, range: [first_seq, last_seq], head }`. `head` is the `hash` of the last record judged |
| `judge` | object | `{ id, model, vendor, view }` as in `vote` |
| `verdict` | string | `clean`, `flagged` or `tampered` |
| `findings` | array | each `{ call_seq, severity, note }`. `severity` is `info`, `warn` or `block`. `note` up to 240 characters, no raw arguments |
| `chain_ok` | boolean | result of `verifyChain` on the subject before the model saw anything |
| `ms` | integer | model latency |

Rules: the judge receives the session records as data, with every `args_summary` removed, and the instruction that nothing in the records is an instruction to it. If `chain_ok` is false the verdict is `tampered` and the model is not called.

### `outcome_label`

Written by `witness score`, one per `tool_call` in the subject session, computed from the stream only.

| Field | Type | Meaning |
|---|---|---|
| `subject` | object | `{ session, call_seq }` |
| `label` | string | `clean`, `flagged`, `overridden` or `refused` |
| `y` | integer | 1 when the call should have been held: label is `flagged`, `refused`, or `overridden` with answer `cancel`. 0 otherwise |
| `evidence` | array of integer | `seq` values of the records that decided the label: the `tool_result`, any `judge` finding with severity `warn` or `block` on this call, any `override`, any `refusal` |

Precedence: `refused` > `overridden` > `flagged` > `clean`. A `judge` record with verdict `tampered` labels every call in its range `flagged`.

### `score`

Written by `witness score`, one per judge per event class per run.

| Field | Type | Meaning |
|---|---|---|
| `judge_id` | string | |
| `event_class` | string | the `tool` name, or `*` for all |
| `n` | integer | votes scored |
| `brier` | number | mean over scored votes of `(p_unsafe - y)^2`, with exponential decay weight `0.5^(age_days / half_life_days)`; `half_life_days` default 14 |
| `abstentions` | integer | assigned calls with no vote from this judge; each counts as `p_unsafe = 0.5` |
| `window` | object | `{ since, until }` ISO-8601 |

Only assigned calls are scored: a vote on a call the judge was not assigned to is ignored. Assignment is the set of `grant.votes` that name the judge.

### `rotation`

Written by `witness score` when a judge reaches its term.

| Field | Type | Meaning |
|---|---|---|
| `judge_id` | string | the retiring instance |
| `role` | string | `worker`, `manager` or `director` |
| `event_class` | string | |
| `term` | object | `{ events, days }` the limit that was reached |
| `successor` | string or null | new `judge.id`, which must differ in `id`; `model` may repeat |

Rank per event class is the ascending order of `brier` among judges with `n >= 20`. The lowest `brier` holds `director` for that class. No `judge.id` may hold `director` in more than 3 classes at once.

## 5. Feed chain

### `feed`

A projection of `refusal`, signed, with nothing else from the session.

| Field | Type | Meaning |
|---|---|---|
| `origin` | object | `{ host_sha256, session }` |
| `indicator` | object | as in `refusal` |
| `reason` | string | as in `refusal` |
| `signer` | object | required on this chain |

A gate reads the feed before a vote and adds a `vote` with `judge.id` `feed`, `view` `metadata`, `p_unsafe` 1.0 and `max_caps` `[]` when a requested indicator digest matches.

## 6. CLI contracts

```
witness judge <session|file> [--model m] [--vendor v] [--key k] [--json]
    Verify the chain. Call a fresh model instance. Append one judge record to judge/<session>.jsonl.
    Exit 0 on clean, 2 on flagged, 3 on tampered, 1 on error.

witness score [--since 30d] [--half-life 14d] [--json]
    Compute outcome_label, score and rotation records for every session with a judgment chain.
    Print a leaderboard: judge_id, event_class, n, brier, rank, role.

witness feed publish [--key k]      Append every new refusal as a feed record.
witness feed pull <url>             Append remote feed records after signature check.
witness feed match <sha256>         Exit 0 when an indicator is present.
```

Model calls go through one adapter interface in `lib/judge.mjs`: `judgeAdapter({ model, vendor }) -> async (records) -> { verdict, findings }`. The first adapters: `anthropic` (API key from `ANTHROPIC_API_KEY`), `openrouter` (`OPENROUTER_API_KEY`), `ollama` (`OLLAMA_HOST`, metadata view only), and `stub` for tests. No adapter stores a key in a record.

## 7. What v0.2 does not claim

A judge can be wrong. A judge can be injected if its view is `full`. The feed trusts whoever holds a key. The score is only as good as the outcome labels, and the labels come from the stream, which is only as complete as what was wrapped. Term limits bound exposure; they do not remove it.
