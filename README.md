# DVC Agent Flight Recorder

A local-first, cross-vendor operational control plane for trustworthy agent inventory, permission posture, activity evidence, runtime health, completion verdicts, and safe control contracts.

## Launch locally

Prerequisite: Node.js 22 or later.

1. Open this project folder.
2. Run `npm install` once.
3. Double-click `Launch Flight Recorder.command`, or run `npm run dev`.
4. The launcher opens `http://localhost:3000` when the recorder is ready.

The launch command refreshes evidence from the configured safe local sources, starts a loopback-only control service, creates one recorder-owned disposable test agent, and starts the interface. It never controls an existing process or repairs an observed source.

This first slice intentionally has no database, hosted identity layer, or cloud telemetry. The local JSONL evidence chain is the source of record.

## Useful checks

- `npm run ingest` refreshes the snapshot and appends collection events.
- `npm run verify:ledger` verifies the full hash chain.
- `npm run export:evidence` creates an operator-controlled evidence bundle under `exports/`.
- `npm test` runs ingestion, ledger verification, a production build, and rendered-interface tests.

Set `TICKET_STORE_ROOT` only when the local TicketBoard store is elsewhere. The default is `/Users/alsharma/Projects/experience-layering-main/ticket_store`.

## Operator onboarding

Start at Overview to see coverage and source failures. Source coverage manifest distinguishes observed state from confirmed absence, unreachable, unsupported, and unconfigured scope. Mission timeline shows ordered claims and evidence ids. Permission & approval matrix distinguishes observed access from policy.

The control section can issue a two-minute, single-use approval for the recorder-owned disposable test agent. Suspend, resume, and terminate are real for that one target only. The service never accepts a PID, executable, or shell command from the interface. Approval and receipt records are stored under `data/control/`; raw approval nonces are never persisted.

Product decisions live in [docs/PRODUCT_BRIEF.md](docs/PRODUCT_BRIEF.md), [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md), and [docs/ADR-001-STACK.md](docs/ADR-001-STACK.md). Privacy rules and the real/simulated/deferred boundary are in [docs/PRIVACY.md](docs/PRIVACY.md) and [docs/STATUS.md](docs/STATUS.md).

The separated loopback control boundary is recorded in [docs/ADR-002-BOUNDED-CONTROL.md](docs/ADR-002-BOUNDED-CONTROL.md).

The evaluator walkthrough is in [docs/PILOT_RUNBOOK.md](docs/PILOT_RUNBOOK.md).
