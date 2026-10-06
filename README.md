# Witness

**A transparent MCP proxy that writes a tamper-evident record of what your AI agents actually did — every tool call, its outcome, its latency — under a declared principal, on your machine, with no dependencies.**

Witness sits between any MCP client (Claude Code, Claude Desktop, Cursor, Cowork, your own harness) and any MCP server. Frames pass through untouched. On the way past, each `tools/call` and its result are digested into an append-only, SHA-256-chained log you can verify, query, and hand to someone else. Arguments and results are hashed, never stored.

> Status: **v0.3: the recorder, plus three readers of its records: `judge`, `score` and `feed`.** Everything in "Real today" runs and is tested. The record format is [SPEC.md](SPEC.md), the readers' records are [SPEC-0.2.md](SPEC-0.2.md), and both are implementable without this code.

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

## Why it exists

Observability tools start after the model is called. Identity tools stop before the agent acts. The question every incident review asks sits in between: *what did the agent do, and can you prove it?* Witness answers the narrowest useful version of that — at the MCP tool boundary, per call, with a chain that detects edits — and refuses to claim more.

Two rules govern the design:

1. **Absence of evidence is never evidence of absence.** Only servers explicitly wrapped are observed. A call the server never answered is recorded as `unknown`, not omitted. The record says `verified: false` next to the principal, because it is.
2. **Relay first, record second.** Nothing in the recording path can delay, alter, or drop a frame.

## Real today (v0.3)

- **MCP stdio proxy.** `witness -- <server command>` relays JSON-RPC between any client and any stdio server, recording `session_start`, the client identity from `initialize`, every `tools/call` with a SHA-256 of its arguments, every result with status (`ok` / `error` / `unknown`), latency, and `session_end` with counts. Non-JSON lines pass through and are recorded as `raw`. Tested for byte-for-byte transparency, outcome classification, secret exclusion, chain verification, tamper detection, and recorder-failure isolation.
- **HTTP / SSE transport.** `witness http --upstream <url>` is a loopback reverse proxy for remote servers. Bodies relay byte-for-byte; `Authorization` passes through and is never recorded; JSON and `text/event-stream` responses are parsed on the way past into the same records; an unreachable upstream answers a JSON-RPC 502 and the call seals as `unknown`.
- **`wrap` / `unwrap`.** Auto-detects `.mcp.json` (Claude Code project), `~/.claude.json`, `~/.cursor/mcp.json`, and Claude Desktop. Reversible, idempotent, dry-run, backup kept. Remote (`url`) entries are reported with the `http` command to run.
- **`verify`, `tail`, `sessions`, `query`, `report`.** Walk chains and exit non-zero on the first broken link; follow the newest session live; list sessions; filter joined call rows by tool, server, principal, status, time; a markdown digest with error rate and p50/p95 latency per tool.
- **`anchor`.** Append every session's chain head to a checkpoints file that is itself chained; `--git` commits it in `WITNESS_HOME` so your repo history is a clock.
- **Declared principal.** `--as you@company` (or `WITNESS_AS`) labels every call. `verified` is always `false` in this version.
- **Secret exclusion by construction.** Keys matching `token | secret | password | authorization | cookie | api_key | credential` never appear in a summary, even when allow-listed with `--allow`.
- **Readers: `judge` and `score`.** `witness judge <session>` verifies a session chain, gives a fresh model only the metadata view (every `args_summary` removed), and appends a `judge` record to `judge/<session>.jsonl`. `witness score` labels every call from the stream and Brier-scores each judge. See [SPEC-0.2.md](SPEC-0.2.md) sections 4 and 6.
- **`keygen`.** `witness keygen` makes an ed25519 key pair in `keys/` and prints its `key_id` (`k_` and the first 8 hex characters of the public key digest). It never overwrites a key. `judge --key` and `feed publish --key` sign with it.
- **Feed relay.** Machines share the indicators of refused calls. `witness feed publish --key <key_id>` signs every new local refusal indicator into `feed/published.jsonl`. `witness feed serve` streams that file read-only on `127.0.0.1:7480` (`--host` and `--port` change it). It refuses `published.jsonl` when that name itself is a symbolic link or a hard link. It follows a link at `feed/` or above (see [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)). It caps replies, concurrent requests and stalled sockets. `witness feed pull <url>` checks every line against the peer's `.pub` in `keys/` and appends the good lines byte for byte to `feed/remote/<key_id>.jsonl`. It stops at the first bad line and exits 3. `witness feed match <sha256>` exits 0 when a digest is in a feed file that verifies, and 2 when any feed file does not verify. Only indicator digests, reasons, a host-name digest and the session id travel. No tool argument travels.

Tested end-to-end against a third-party server (desktop-commander 0.2.50, 26 tools): transparent relay, correct ok/error classification, hashed arguments, verified chain.

## What it does not claim

No proven identity, no signature on session records (only judge and feed records carry one), no external timestamp, no enforcement, no inventory of servers you did not wrap. A chain proves *internal* consistency and detects edits after the fact; an administrator with filesystem access can replace both the log and the verifier. [SPEC.md](SPEC.md) states this per field; [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) states it per adversary.

## Using it as a library

```js
import { verifyChain, sealRecord, canonical } from "@darkvectorcognition.ai/witness";
import { readRecords, listSessionFiles } from "@darkvectorcognition.ai/witness/session-log";
import { loadCalls, buildReport } from "@darkvectorcognition.ai/witness/analyze";
```

## What it never does

- No product telemetry, hosted account, cloud database, or background upload.
- No record leaves the machine except through two commands that you run. `witness judge` sends session metadata to the model vendor you pick. `witness feed serve` answers every host that can reach the address you bind. See [docs/PRIVACY.md](docs/PRIVACY.md).
- No collection of API keys, bearer tokens, cookies, passwords, authorization headers, tool arguments, tool results, prompt bodies, or environment-variable values.
- No control of any process. It relays and records; it never blocks, rewrites, or approves a call.

Details: [docs/PRIVACY.md](docs/PRIVACY.md), [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Run from source

Node.js 22.13 or later. No install step.

```bash
git clone https://github.com/dark-vector-cognition/witness && cd witness
node bin/witness.mjs --help
npm test     # ~20 seconds, no build
```

## Contributing

Small pull requests that keep the recorder dependency-free and the README honest. Commits need a DCO sign-off — see [CONTRIBUTING.md](CONTRIBUTING.md).

## Using it commercially

Witness is free to run, fork, and embed under [Apache-2.0](LICENSE). It is complete for one engineer on one machine. If you want an organisation's agent estate read for you — servers inventoried, permissions mapped, ten days of records analysed, findings ranked, and a remediation plan your engineers can act on — that is Dark Vector Cognition's [Agent Flight Check](https://darkvectorcognition.ai/flight-check/): two weeks, fixed price, nothing leaves your network.

Dark Vector Cognition LLC · Austin, Texas · hello@darkvectorcognition.ai
