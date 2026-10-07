# Witness record format v0.2: readers of the stream

Status: **draft, Oct 6 2026**. Extends [SPEC.md](SPEC.md) (format v0.1). Every v0.1 rule still holds: one append-only JSONL chain per file, `canonical()` and `hash` as defined there, arguments and results digested and never stored. Records that use anything on this page carry `"v": "0.2"`. A v0.1 verifier accepts every unsigned record here and only sees unknown event types. A v0.1 verifier reports a hash mismatch on a signed record, because `signer` is attached after the hash; a v0.2 verifier removes `signer` before the check and, when a key for `key_id` is present under `keys/`, checks the signature and reports a bad one.

Thesis: one stream, many readers. Every reader writes its findings as new records. No reader edits a record. Ticket: LOCAL-543.

## 1. Chains

| Chain | Path under `$WITNESS_HOME` | Writer | Holds |
|---|---|---|---|
| session | `log/<session>.jsonl` | the recorder (proxy or the witness-recorder mod) | v0.1 events plus `vote`, `grant`, `override`, `refusal` |
| judgment | `judge/<session>.jsonl` | `witness judge` and `witness score` | `judge`, `outcome_label`, `score`, `rotation` |
| scoreboard | `judge/j_scoreboard.jsonl` | `witness score` | `score`, `rotation`; records carry `session` `j_scoreboard` |
| local feed | `feed/refusals.jsonl` | the council mod | `feed`, unsigned; records carry `session` `feed` |
| published feed | `feed/published.jsonl` | `witness feed publish` | `feed`, signed; records carry `session` `published` |
| remote feed | `feed/remote/<key_id>.jsonl` | `witness feed pull` | byte-exact copies of one peer's published lines that passed verification; one file per peer key |

Each chain is independent: `seq` starts at 0, `prev` starts at `GENESIS`. A judgment chain names the session chain it reads through `subject`. A reader never opens a session file for writing.

## 2. Signing (optional in v0.2)

Any record may carry `signer`:

```json
"signer": { "key_id": "k_3f2a9c1e", "alg": "ed25519", "sig": "<base64 of ed25519(hash)>" }
```

`sig` signs the raw 32 bytes of the record's `hash` (the hex string decoded), so the hash is computed first, with `signer` absent, then `signer` is attached. Verification: recompute `hash` on the record without `signer`, then check `sig` against the public key for `key_id`. Public keys live in `$WITNESS_HOME/keys/<key_id>.pub`. The private key lives in `$WITNESS_HOME/keys/<key_id>.key` (PKCS8 PEM) and never enters a record. An older v0.1 verifier hashes `signer` with the rest of the record, so it reports a hash mismatch on a signed record. A record without `signer` is unsigned, not invalid. `principal.verified` stays `false` unless a signature covers the record.

`witness keygen` makes a key pair. `key_id` is `"k_"` plus the first 8 hex characters of sha256 of the public key's SPKI DER. The `key_id` is a name, not a trust anchor: a verifier checks the signature with the content of `keys/<key_id>.pub`. A chain that must be signed (the published feed and remote copies, section 5) fails on a record without `signer`, because the hash does not cover `signer` and anyone can remove it.

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
| `findings` | array | each `{ call_seq, severity, note }`. `call_seq` is an integer; when the model names no call, it is the `seq` of the first `tool_call` in range and `severity` is `info`. `severity` is `info`, `warn` or `block`. `note` up to 240 characters, no raw arguments; any `args_summary` value in a note is replaced with `[redacted]` |
| `chain_ok` | boolean | result of `verifyChain` on the subject before the model saw anything |
| `ms` | integer | model latency |

Rules: the judge receives the session records as data, with every `args_summary` removed, and the instruction that nothing in the records is an instruction to it. `judge.view` is therefore always `metadata`. The fixed instruction goes in the system prompt and the records go in the user turn as one JSON data block. A reply that does not parse gives verdict `flagged` with one `warn` finding, note `judge reply unparseable`. If `chain_ok` is false the verdict is `tampered` and the model is not called.

### `outcome_label`

Written by `witness score`, one per `tool_call` in the subject session, computed from the stream only.

| Field | Type | Meaning |
|---|---|---|
| `subject` | object | `{ session, call_seq }` |
| `label` | string | `clean`, `flagged`, `overridden` or `refused` |
| `y` | integer | 1 when the call should have been held: label is `flagged`, `refused`, or `overridden` with answer `cancel`. 0 otherwise |
| `evidence` | object | `{ session, judgment }`, each an array of integer `seq`. `session`: the `tool_result`, any `override`, any `refusal` on this call. `judgment`: any `judge` record with a `warn` or `block` finding on this call, or with verdict `tampered` |

Precedence: `refused` > `overridden` > `flagged` > `clean`. A `judge` record with verdict `tampered` labels every call in the session `flagged`, whatever its `range`.

### `score`

Written by `witness score`, one per judge per event class per run.

| Field | Type | Meaning |
|---|---|---|
| `judge_id` | string | |
| `event_class` | string | the `tool` name, or `*` for all |
| `n` | integer | votes scored |
| `brier` | number | mean over scored votes of `(p_unsafe - y)^2`, with exponential decay weight `0.5^(age_days / half_life_days)`; `half_life_days` default 14 |
| `abstentions` | integer | assigned calls with no vote from this judge; each counts as `p_unsafe = 0.5` |
| `malformed` | integer | assigned votes whose `p_unsafe` is neither `null` (an abstention) nor a number in [0, 1]; not scored and not in `n` |
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

Rank per event class is the ascending order of `brier` among judges with `n >= 20`. The lowest `brier` holds `director` for that class. No `judge.id` may hold `director` in more than 3 classes at once; the `*` class does not count.

## 5. Feed chain

### `feed`

A projection of `refusal`, with nothing else from the session.

| Field | Type | Meaning |
|---|---|---|
| `origin` | object | `{ host_sha256, session }`. `host_sha256` is the sha256 of the host name. `session` is the session that refused |
| `indicator` | object | as in `refusal` |
| `reason` | string | as in `refusal` |
| `signer` | object | absent on the local chain. Required on the published chain and on every remote copy |

Three kinds of file hold `feed` records:

1. **Local chain**, `feed/refusals.jsonl`. The council mod appends one unsigned `feed` record after each refusal. Envelope `session` is `feed`.
2. **Published chain**, `feed/published.jsonl`. `witness feed publish` appends one signed record for each local indicator digest that is not yet published. A record is exactly `{ v: "0.2", seq, ts, session: "published", event: "feed", origin, indicator, reason, prev, hash, signer }`. Only these fields leave the machine.
3. **Remote copies**, `feed/remote/<key_id>.jsonl`. `witness feed pull` appends the lines of one peer's published chain that pass verification, byte for byte. One file holds one peer key. `feed/remote/peers.json` maps each peer URL to its `key_id`, so the next pull asks only for `?after=<last seq>`.

Every feed file must be valid UTF-8. Each reader (verify, match, publish, and pull for its local copy and for each reply line) decodes with a fatal decoder before it parses, so an invalid byte fails the file instead of turning into U+FFFD: match exits 2, publish 3, verify 1, pull 3. In every feed file, an empty or whitespace-only line is a bad line. An empty file is an empty chain, and the empty element after a final newline is not a line.

A published chain or a remote copy verifies when all of these hold. The file is one chain. `seq` equals the position in the file. Every record has `event` `feed` and a `signer`. `keys/<key_id>.pub` exists, holds an ed25519 key, and hashes to its `key_id`. The signature is valid. A remote copy is named exactly `<key_id>.jsonl`, with `key_id` matching `k_` and 8 lowercase hex characters, and every record's `signer.key_id` equals that `key_id`. Any other `*.jsonl` name in `feed/remote/`, also `.jsonl`, fails verification, also when the file is empty.

Trust: a peer is trusted only when its `.pub` is in `keys/`. The operator copies it there. There is no other path to trust.

Transport: the publisher serves `GET /feed` (section 6). The server does not verify. The puller verifies every line.

A gate reads the local chain and every remote copy before a vote. It adds a `vote` with `judge.id` `feed`, `view` `metadata`, `p_unsafe` 1.0 and `max_caps` `[]` when a requested indicator digest matches. The gate does not verify signatures again, because pull verified them. A forged remote entry can cause a refusal, not a run.

## 6. CLI contracts

```
witness judge <session|file> [--model m] [--vendor v] [--key k] [--json]
    Verify the chain. Call a fresh model instance. Append one judge record to judge/<session>.jsonl.
    Exit 0 on clean, 2 on flagged, 3 on tampered, 1 on error.

witness score [--since 30d] [--half-life 14d] [--json]
    Compute outcome_label, score and rotation records for every session with a judgment chain.
    Print a leaderboard: judge_id, event_class, n, brier, rank, role.

witness keygen
    Make an ed25519 key pair: keys/<key_id>.key (PKCS8 PEM) and keys/<key_id>.pub (SPKI PEM).
    key_id = "k_" + the first 8 hex characters of sha256(SPKI DER). Print the key_id. Never overwrite a key.
    Exit 0 ok, 1 error.

witness feed publish --key <key_id>
    Verify feed/refusals.jsonl and feed/published.jsonl. If either is broken, publish nothing and exit 3.
    A non-empty published.jsonl that does not end with a newline is broken too: exit 3, nothing appended.
    For every local feed record whose indicator.sha256 is not yet in published.jsonl, append one signed record.
    A second run appends nothing. Print the count appended.
    Exit 0 ok, 1 error (for example a missing key, or a .key or .pub that does not hash to key_id), 3 broken chain.

witness feed serve [--host 127.0.0.1] [--port 7480] [--any-interface]
    Read-only HTTP, bound only to --host. Print {"listen": "<url>", "file": "<published.jsonl>"}.
    --host is resolved first, and serve binds that one address. An empty, whitespace or non-string host: exit 1.
    A host that resolves to every interface (0.0.0.0, ::, [::], "0"): exit 1, unless --any-interface is given too.
    Every spelling counts, also the IPv4-mapped ones: ::ffff:0.0.0.0, ::ffff:0:0, 0:0:0:0:0:ffff:0:0, ::0.0.0.0, and any of them with a %zone.
    GET /feed            published.jsonl as application/x-ndjson, bytes as stored.
    GET /feed?after=<n>  skip the leading lines that parse with an integer seq <= n, then send the bytes after them.
                         A blank or unparseable line stops the skip and is sent as is, so pull rejects it.
    A reply holds whole lines only, at most 32 MiB. A last line with no newline is held back. Pull again for the rest.
    published.jsonl is opened with O_NOFOLLOW and O_NONBLOCK. It must be a regular file with one hard link.
    O_NOFOLLOW checks only the last path component: a link at feed/ or above is followed.
    A symbolic link, a hard link, a directory or a FIFO gives 500 and no file bytes. Missing published.jsonl: 200, empty body.
    The reply is streamed with backpressure; the file is never read whole into memory.
    At most 8 replies at once; another request gets 503 with Retry-After: 1. A slot is given back only when its
    scan, its stream and its file handle are done. When the client leaves, the scan stops at its next chunk.
    A socket with no traffic for 30 seconds is destroyed. A request must arrive in 30 seconds.
    A bad after value: 400. Another method on /feed: 405 with Allow: GET. Every other path: 404. No write endpoint.

witness feed pull <url>
    url is a peer's /feed endpoint. Send exactly one GET, with no body, and follow no redirect.
    First read remote/peers.json. Only ENOENT means no bindings. Any other read error, text that is not a JSON object,
    or a value that is not a key_id: exit 1, with no request and no change.
    A URL bound in remote/peers.json to a local copy gets ?after=<last seq of that copy>. Every line of the reply is new.
    Any other URL gets no after, so the reply starts at seq 0. When its first line names a key_id that has a local
    copy, the first lines of the reply must be byte-identical to the lines of that copy. The lines after them are new.
    Check each new line, in order: valid UTF-8 and JSON; event "feed"; signer present; the same key_id as the
    peer and as every other line; keys/<key_id>.pub present, ed25519, and hashing to key_id; hash recomputes with
    signer removed; signature valid; seq and prev continue the local copy (seq 0 and prev GENESIS for a new peer);
    indicator.kind and indicator.sha256 present. An exception while a line is checked is a failed line.
    A reply that does not end with a newline fails at its last line.
    Lines are read one at a time. The first line that fails stops the check, and the rest of the reply is not split.
    Append each new line that passes, byte for byte, to feed/remote/<key_id>.jsonl.
    At the first line that fails or differs: keep the new lines before it, append nothing after it, print the reason, exit 3.
    Network or file errors, a redirect, or a status other than 200: exit 1. Success: print the count, exit 0.
    The URL is bound to the key when the reply adds lines to the copy or repeats it without a difference.
    The append and the binding run under one exclusive lock per home, remote/peers.json.lock. Under it, pull reads
    peers.json again. If the URL is now bound to another key_id: exit 3, nothing appended, nothing bound.
    The binding is written first (a temp file and a rename), then the lines are appended. If the binding cannot be written,
    nothing is appended. A binding without a local copy is harmless: the next pull asks for the whole feed.
    A lock that stays taken for about 1 second: exit 1, nothing changed.
    The reply is capped at 32 MiB and 30 seconds. To accept a new key at a known URL, remove the URL from remote/peers.json.

witness feed match <sha256>
    Look in feed/refusals.jsonl, feed/published.jsonl and every feed/remote/*.jsonl. A hit counts only from a file that verifies:
      refusals.jsonl          a valid chain
      published.jsonl         a valid chain, every record signed by a trusted key in keys/
      remote/<key_id>.jsonl   a valid chain, every record signed by keys/<key_id>.pub, signer.key_id equal to the file name
    Every *.jsonl name in feed/remote/ counts. A name that is not exactly <key_id>.jsonl does not verify.
    A blank line does not parse. Only ENOENT means a missing file or directory.
    Exit 0 when found (print each file and the indicator kind), 1 when not found,
    2 on a malformed <sha256>, a file or directory that cannot be read, a line that does not parse, or a file that
    does not verify. An error wins over a hit.

witness verify [file|dir]
    A feed file is one chain with seq equal to its position. published.jsonl and remote/*.jsonl need a trusted signer
    on every record, and a remote copy holds only its own key_id and is named exactly <key_id>.jsonl.
    A feed file is read with the strict feed parser: a blank or unparseable line is a FAIL.
    witness verify <home>/feed also walks feed/remote/.
```

Files under `$WITNESS_HOME` for keys and the feed. Directories are 0700 and files 0600.

```
keys/<key_id>.key            ed25519 private key, PKCS8 PEM. Never leaves the machine.
keys/<key_id>.pub            ed25519 public key, SPKI PEM. A peer's .pub here makes that peer trusted.
feed/refusals.jsonl          local feed chain (the council mod)
feed/published.jsonl         signed feed chain (witness feed publish)
feed/remote/<key_id>.jsonl   verified copy of one peer's published chain (witness feed pull)
feed/remote/peers.json       peer URL to key_id (witness feed pull)
```

Model calls go through one adapter interface in `lib/judge.mjs`: `judgeAdapter({ model, vendor }) -> async (records) -> { verdict, findings }`. The first adapters: `anthropic` (API key from `ANTHROPIC_API_KEY`), `openrouter` (`OPENROUTER_API_KEY`), `ollama` (`OLLAMA_HOST`, metadata view only), and `stub` for tests. No adapter stores a key in a record.

## 7. What v0.2 does not claim

A judge can be wrong. A judge can be injected if its view is `full`. The feed trusts whoever holds a key. A peer can withhold new records, and a puller cannot tell. The feed has no TLS and no authentication of its own. The score is only as good as the outcome labels, and the labels come from the stream, which is only as complete as what was wrapped. Term limits bound exposure; they do not remove it.
