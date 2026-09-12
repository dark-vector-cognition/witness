# Witness — the DVC Agent Flight Recorder

**A local-first, cross-vendor record of what the AI agents in your company exist, what they can touch, who approved that, and what they actually did — with evidence you can hand to an auditor.**

Witness is the instrument behind [Agent Flight Check](https://darkvectorcognition.ai/flight-check/), Dark Vector Cognition's two-week, fixed-price audit of an organisation's agent estate. The recorder is open source under Apache-2.0 and complete for one engineer on one machine. The Flight Check is where an organisation buys the reading of it.

> Status: **v0.2 — working local MVP.** Everything in the "Real today" section below runs, is tested, and has been exercised end-to-end. Everything under "Next" is not built yet. We would rather you find that out here than after an install.

## Why it exists

Every company now has agents acting on production systems — coding agents, MCP servers, connectors, internal automations — and almost nobody has the list. Observability tools start after the model is called. Identity tools stop before the agent acts. In between sits the question every incident review and every board now asks: *what did the agents do, and can you prove it?*

Witness answers that question with an evidence chain that links four things most tools keep apart:

```
inventory  →  authorization  →  action  →  outcome
what exists    who approved what   what happened   did it complete, and what proves it
```

Two rules govern the whole design:

1. **Absence of evidence is never evidence of absence.** Every collector declares a *coverage manifest* — what it observed, what it confirmed absent, and what was unreachable, unsupported, or simply never configured. A recorder that overclaims is worse than no recorder.
2. **Observation before control.** Reading is safe by default. Any control operation (suspend, resume, terminate) requires an explicit, expiring, single-use approval, produces a receipt, and fails closed.

## Real today (v0.2)

- **Append-only evidence ledger.** Every collection and control event is a JSONL record, SHA-256 chained to the previous one. `npm run verify:ledger` re-walks the whole chain; a 41-event chain has been verified end-to-end.
- **Coverage manifests.** Each adapter emits a discovery envelope and a verdict — *observed / absent / unreachable / unsupported / unconfigured* — with its known limitations stated in the record, not in the marketing.
- **Inventory and health.** Agents, models, MCP servers, connectors, and local runtimes normalised into one snapshot, with reachability and allow-listed version fields.
- **Permission and approval matrix.** Observed access is shown separately from stated policy, so the gap between "what it can do" and "what it was allowed to do" is visible.
- **Bounded control.** A loopback-only (`127.0.0.1`) control service that can suspend, resume, and terminate one *recorder-owned* disposable test agent. Approvals are two-minute, single-use, nonce-bound; only the nonce hash is persisted. The service never accepts an arbitrary PID, executable, path, or shell command from the interface. A browser-verified `running → suspended → running` cycle produces durable receipts.
- **Evidence export.** `npm run export:evidence` writes an operator-controlled bundle (JSON) with the verified chain — the artefact a Flight Check readout is built from.
- **Secret exclusion by construction.** Collectors strip any key matching `token | secret | password | authorization | cookie | api_key | credential` recursively, and the test suite asserts that no such key reaches the snapshot or the export.
- **Three reference adapters** for local sources (a Markdown ticket store, a localhost retrieval service, and a read-only ComfyUI runtime over a private network), included as worked examples of the adapter contract.
- **Operator interface.** Overview, coverage, mission timeline, permission matrix, and control — readable by an IT director without a terminal.

## Not built yet ("Next")

These are the gaps between v0.2 and the full Flight Check promise, in the order we are closing them:

1. **MCP proxy adapter.** A transparent proxy that sits in front of MCP servers and records every tool call as a ledger event. This is what turns "ten days of records" from a claim into a file. Spec is written; this is the current build.
2. **Cross-vendor adapter contract with conformance tests**, so a new adapter cannot silently overclaim coverage.
3. **Device-backed operator identity** to replace `local-user@machine` in approval receipts.
4. Signed source events, external timestamping, and tamper-resistant storage.
5. Continuous collectors, retention policy, search, multi-machine federation, RBAC/SSO, packaged enterprise deployment.

The full truth ledger — real, simulated, deferred, and commercially risky — is kept current in [docs/STATUS.md](docs/STATUS.md).

## Run it

Prerequisite: Node.js 22.13 or later.

```bash
npm install
npm run dev          # ingests from configured sources, starts the control service, opens http://localhost:3000
npm run verify:ledger
npm run export:evidence
npm test             # ingest + ledger verification + production build + rendered-interface tests
```

On macOS, `Launch Flight Recorder.command` does the same by double-click.

The reference adapters are configured by environment variable and degrade to a declared coverage status when unset — never a crash:

| Variable | Adapter | When unset |
|---|---|---|
| `TICKET_STORE_ROOT` | Markdown ticket store | `not_configured` |
| `VAULT_RAG_HEALTH_URL` | localhost retrieval service (default `http://127.0.0.1:8742/health`) | probed; `unreachable` if absent |
| `STORMBREAKER_STATS_URL` | read-only ComfyUI `system_stats` on a private network | `not_configured` (not probed) |
| `LOCAL_MODELS_URL` | unauthenticated local model list (default `http://127.0.0.1:1234/v1/models`) | probed; `not_configured` if absent |

A fresh clone with nothing configured still ingests, verifies its chain, builds, and passes `npm test`.

## What it never does

- No product telemetry, hosted account, cloud database, or background upload. The local ledger is the source of record.
- No collection of API keys, bearer tokens, cookies, passwords, authorization headers, prompt bodies, retrieved documents, customer records, generated media, or environment-variable values.
- No control of any process it did not create, in this release.

Details: [docs/PRIVACY.md](docs/PRIVACY.md) and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Design record

- [docs/PRODUCT_BRIEF.md](docs/PRODUCT_BRIEF.md) — buyer, pain, promise, wedge, risks
- [docs/ADR-001-STACK.md](docs/ADR-001-STACK.md) — why this stack
- [docs/ADR-002-BOUNDED-CONTROL.md](docs/ADR-002-BOUNDED-CONTROL.md) — the loopback control boundary
- [docs/PILOT_RUNBOOK.md](docs/PILOT_RUNBOOK.md) — the evaluator walkthrough used in a Flight Check
- [docs/STATUS.md](docs/STATUS.md) — the truth ledger

## Using it commercially

Witness is free to run, fork, and embed under [Apache-2.0](LICENSE). If you want it read for you — inventory reconciled, permissions mapped, ten days of records analysed, findings ranked, and a remediation plan your engineers can act on — that is the [Agent Flight Check](https://darkvectorcognition.ai/flight-check/): two weeks, fixed price, nothing leaves your network.

Dark Vector Cognition LLC · Austin, Texas · hello@darkvectorcognition.ai
