# DVC Agent Flight Recorder

A local-first, cross-vendor operational control plane for trustworthy agent inventory, permission posture, activity evidence, runtime health, completion verdicts, and safe control contracts.

## Launch locally

Prerequisite: Node.js 22 or later.

1. Open this project folder.
2. Run `npm install` once.
3. Run `npm run dev`.
4. Open `http://localhost:3000`.

The launch command refreshes evidence from the configured safe local sources before starting the interface. It does not start, stop, or repair those sources.

This first slice intentionally has no database, hosted identity layer, or cloud telemetry. The local JSONL evidence chain is the source of record.

## Useful checks

- `npm run ingest` refreshes the snapshot and appends collection events.
- `npm run verify:ledger` verifies the full hash chain.
- `npm test` runs ingestion, ledger verification, a production build, and rendered-interface tests.

Set `TICKET_STORE_ROOT` only when the local TicketBoard store is elsewhere. The default is `/Users/alsharma/Projects/experience-layering-main/ticket_store`.

## Operator onboarding

Start at Overview to see coverage and source failures. Use Mission timeline to inspect ordered claims and evidence ids. Permission & approval matrix distinguishes observed access from policy. Controls are intentionally labeled simulation-only; a receipt proves only that the contract UI was exercised.

Product decisions live in [docs/PRODUCT_BRIEF.md](docs/PRODUCT_BRIEF.md), [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md), and [docs/ADR-001-STACK.md](docs/ADR-001-STACK.md). Privacy rules and the real/simulated/deferred boundary are in [docs/PRIVACY.md](docs/PRIVACY.md) and [docs/STATUS.md](docs/STATUS.md).
