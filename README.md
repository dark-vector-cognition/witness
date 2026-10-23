# Witness

**A transparent MCP proxy that writes a tamper-evident record of what your AI agents actually did — every tool call, its outcome, its latency — under a declared principal, on your machine, with no dependencies.**

Witness sits between any MCP client (Claude Code, Claude Desktop, Cursor, Cowork, your own harness) and any MCP server. Frames pass through untouched. On the way past, each `tools/call` and its result are digested into an append-only, SHA-256-chained log you can verify, query, and hand to someone else. Arguments and results are hashed, never stored.

> Status: **v0.4: the recorder, three readers of its records (`judge`, `score` and `feed`), and a countersigned logbook (`seal`, `notary`, `countersign`, `check`).** Everything in "Real today" runs and is tested. The record format is [SPEC.md](SPEC.md), the readers' records are [SPEC-0.2.md](SPEC-0.2.md), heads and receipts are [SPEC-0.4.md](SPEC-0.4.md), and all three are implementable without this code.

## 60-second start

```bash
npx @darkvectorcognition.ai/witness wrap --as you@company   # rewrites your MCP config; keeps a .witness-bak
# restart the harness, use it normally, then:
npx @darkvectorcognition.ai/witness tail      # live: every tool call, its outcome, its latency
npx @darkvectorcognition.ai/witness verify    # walk every chain; exit 1 on the first broken link
npx @darkvectorcognition.ai/witness report    # markdown digest of the last 7 days
```

Or wrap one server by hand, in `.mcp.json` / `claude_desktop_config.json` / Cursor's `mcp.json`:

```json
"github": {
  "command": "npx",
  "args": ["-y", "@darkvectorcognition.ai/witness", "--as", "you@company", "--",
           "npx", "-y", "@modelcontextprotocol/server-github"]
}
```

For a remote (Streamable HTTP or SSE) server:

```bash
npx @darkvectorcognition.ai/witness http --upstream https://mcp.example.com/mcp --as you@company
# prints a 127.0.0.1 address — point the config's "url" at it
```

Records live in `~/.witness/log/<session>.jsonl` (`WITNESS_HOME` to move them). If Witness cannot write its log it says so on stderr and keeps relaying: breakage can cost records, never uptime.

## Countersign quick start

A notary is another party with its own Witness home and key. It receipts your signed chain heads in a chain you do not hold.

```bash
# the notary, on its own machine and home
witness keygen                                   # prints its key_id, say k_7b04d6a2, and its fingerprint; give its .pub to the operator
witness notary serve --key k_7b04d6a2            # POST /receipt on 127.0.0.1:7481

# the operator
witness keygen                                   # k_3f2a9c1e
cp k_7b04d6a2.pub ~/.witness/keys/               # trust the notary key
witness countersign http://127.0.0.1:7481/receipt --all --key k_3f2a9c1e --notary <notary fingerprint>

# anyone, offline, with copies of log/, heads/ and receipts/ for one session and the notary .pub in keys/
WITNESS_HOME=./copy witness check s_1a2b3c4d --notary <notary fingerprint>
```

`check` exits 0 when the chain is intact, the record at the sealed `seq` has the sealed hash, the head is signed, and a receipt signed by the notary names that head. Receipts from other notaries are skipped with a note, so a session countersigned with two notaries checks under either key. Each other outcome has its own exit code ([SPEC-0.4.md](SPEC-0.4.md) section 4). The fingerprint is 64 hex characters; a `key_id` also works but holds only 32 bits, and check says so.

## Why it exists

Observability tools start after the model is called. Identity tools stop before the agent acts. The question every incident review asks sits in between: *what did the agent do, and can you prove it?* Witness answers the narrowest useful version of that — at the MCP tool boundary, per call, with a chain that detects edits — and refuses to claim more.

Two rules govern the design:

1. **Absence of evidence is never evidence of absence.** Only servers explicitly wrapped are observed. A call the server never answered is recorded as `unknown`, not omitted. The record says `verified: false` next to the principal, because it is.
2. **Relay first, record second.** Nothing in the recording path can delay, alter, or drop a frame.

## Real today (v0.4)

- **MCP stdio proxy.** `witness -- <server command>` relays JSON-RPC between any client and any stdio server, recording `session_start`, the client identity from `initialize`, every `tools/call` with a SHA-256 of its arguments, every result with status (`ok` / `error` / `unknown`), latency, and `session_end` with counts. Non-JSON lines pass through and are recorded as `raw`. Tested for byte-for-byte transparency, outcome classification, secret exclusion, chain verification, tamper detection, and recorder-failure isolation.
- **HTTP / SSE transport.** `witness http --upstream <url>` is a loopback reverse proxy for remote servers. Bodies relay byte-for-byte; `Authorization` passes through and is never recorded; JSON and `text/event-stream` responses are parsed on the way past into the same records; an unreachable upstream answers a JSON-RPC 502 and the call seals as `unknown`.
- **`wrap` / `unwrap`.** Auto-detects `.mcp.json` (Claude Code project), `~/.claude.json`, `~/.cursor/mcp.json`, and Claude Desktop. Reversible, idempotent, dry-run, backup kept. Remote (`url`) entries are reported with the `http` command to run.
- **`verify`, `tail`, `sessions`, `query`, `report`.** Walk chains and exit non-zero on the first broken link; follow the newest session live; list sessions; filter joined call rows by tool, server, principal, status, time; a markdown digest with error rate and p50/p95 latency per tool.
- **`anchor`.** Append every session's chain head to a checkpoints file that is itself chained; `--git` commits it in `WITNESS_HOME` so your repo history is a clock.
- **Declared principal.** `--as you@company` (or `WITNESS_AS`) labels every call. `verified` is always `false` in this version.
- **Secret exclusion by construction.** Keys matching `token | secret | password | authorization | cookie | api_key | credential` never appear in a summary, even when allow-listed with `--allow`.
- **Readers: `judge` and `score`.** `witness judge <session>` verifies a session chain, gives a fresh model only the metadata view (every `args_summary` removed), and appends a `judge` record to `judge/<session>.jsonl`. `witness score` labels every call from the stream and Brier-scores each judge. See [SPEC-0.2.md](SPEC-0.2.md) sections 4 and 6.
- **`keygen`.** `witness keygen` makes an ed25519 key pair in `keys/` and prints its `key_id` (`k_` and the first 8 hex characters of the public key digest). It never overwrites a key. `judge --key` and `feed publish --key` sign with it.
- **Feed relay.** Machines share the indicators of refused calls. `witness feed publish --key <key_id>` signs every new local refusal indicator into `feed/published.jsonl`. `witness feed serve` streams that file read-only on `127.0.0.1:7480` (`--host` and `--port` change it; an empty `--host` is refused, and `0.0.0.0` or `::` needs `--any-interface`). It refuses `published.jsonl` when that name itself is a symbolic link or a hard link. It follows a link at `feed/` or above (see [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)). It caps replies, concurrent requests and stalled sockets. `witness feed pull <url>` checks every line against the peer's `.pub` in `keys/` and appends the good lines byte for byte to `feed/remote/<key_id>.jsonl`. It stops at the first bad line and exits 3. `witness feed match <sha256>` exits 0 when a digest is in a feed file that verifies, and 2 when any feed file does not verify. Only indicator digests, reasons, a host-name digest and the session id travel. No tool argument travels.

- **Countersigned logbook.** `witness seal [<session>|--all] --key <key_id>` verifies a session chain and appends a head statement to `heads/<session>.jsonl`: session, `seq` and `hash` of the last record, record count, time, `key_id`, the public key, and an ed25519 signature over the canonical statement. `witness notary serve --key <key_id>` is the notary: `POST /receipt` checks the head's signature and that its `key_id` matches its public key, appends a signed receipt to its own chain `notary/log.jsonl`, and returns it. It has the host rules of `feed serve`, a 64 KiB body cap, 8 requests at once, a 30-second stall limit, and `--rate` requests per second for all clients together (default 10, then 429). `witness countersign <url>` seals when needed, sends each head, checks the receipt names that head and, with the notary `.pub` in `keys/`, its signature, then appends it to `receipts/<session>.jsonl`. `witness check <session> --notary <key_id>` runs offline on copies of the files and public keys and gives a distinct exit code per failure. `witness notary verify` walks the notary chain. See [SPEC-0.4.md](SPEC-0.4.md).

Tested end-to-end against a third-party server (desktop-commander 0.2.50, 26 tools): transparent relay, correct ok/error classification, hashed arguments, verified chain.

## What it does not claim

No proven identity, no signature on individual session records, no trusted time authority, no enforcement, no inventory of servers you did not wrap. A chain proves *internal* consistency and detects edits after the fact; an administrator with filesystem access can replace both the log and the verifier on that machine. A countersigned head moves one fact off the machine: a notary you choose holds a signed receipt that a chain with this head existed at its clock's time. That covers records up to the sealed `seq` only, says nothing about whether any record is true, and proves nothing when the notary colludes with the operator. An operator can countersign a rewritten log later; the rewrite shows only against an earlier receipt or, with `check --notary-log`, against a copy of the notary's log. The principal is still `verified: false`. [SPEC.md](SPEC.md) and [SPEC-0.4.md](SPEC-0.4.md) state this per field; [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) states it per adversary. [docs/FIELD-MAP.md](docs/FIELD-MAP.md) maps the record fields to the audit-event list of IETF draft-ietf-wimse-aims-00 Section 11, and says which items Witness does not record.

## Using it as a library

```js
import { verifyChain, sealRecord, canonical } from "@darkvectorcognition.ai/witness";
import { readRecords, listSessionFiles } from "@darkvectorcognition.ai/witness/session-log";
import { loadCalls, buildReport } from "@darkvectorcognition.ai/witness/analyze";
import { checkSession } from "@darkvectorcognition.ai/witness/check";
```

## What it never does

- No product telemetry, hosted account, cloud database, or background upload.
- No record leaves the machine except through three commands that you run. `witness judge` sends session metadata to the model vendor you pick. `witness feed serve` answers every host that can reach the address you bind. `witness countersign` sends one head statement per session (session id, last `seq` and `hash`, record count, time, `key_id`, public key, signature) to the notary URL you give. See [docs/PRIVACY.md](docs/PRIVACY.md).
- No collection of API keys, bearer tokens, cookies, passwords, authorization headers, tool arguments, tool results, prompt bodies, or environment-variable values.
- No control of any process. It relays and records; it never blocks, rewrites, or approves a call.

Details: [docs/PRIVACY.md](docs/PRIVACY.md), [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Run from source

Node.js 22.13 or later. No install step.

```bash
git clone https://github.com/dark-vector-cognition/witness && cd witness
node bin/witness.mjs --help
npm test     # ~25 seconds, no build
```

## Contributing

Small pull requests that keep the recorder dependency-free and the README honest. Commits need a DCO sign-off — see [CONTRIBUTING.md](CONTRIBUTING.md).

## Using it commercially

Witness is free to run, fork, and embed under [Apache-2.0](LICENSE). It is complete for one engineer on one machine. If you want an organisation's agent estate read for you — servers inventoried, permissions mapped, ten days of records analysed, findings ranked, and a remediation plan your engineers can act on — that is Dark Vector Cognition's [Agent Flight Check](https://darkvectorcognition.ai/flight-check/): two weeks, fixed price, nothing leaves your network.

Dark Vector Cognition LLC · Austin, Texas · hello@darkvectorcognition.ai
