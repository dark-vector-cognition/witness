# ADR-001: local collector plus portable operator UI

Status: accepted for MVP

## Decision

Use a small Node.js collection process, a newline-delimited hash-chained evidence ledger on the local filesystem, a generated sanitized snapshot, and a TypeScript/React operator UI built with the existing vinext starter. Source adapters are plain modules with read-only, bounded probes. Live control adapters are a separate future boundary; the MVP exposes and tests contracts but executes simulations only.

## Why this stack

- Node and TypeScript cover collector, schema, tests, and interface without a second application framework.
- JSONL is inspectable, append-friendly, recoverable, and appropriate for the first local evidence chain.
- A generated snapshot cleanly prevents the browser from gaining arbitrary filesystem access.
- The interface can later ship as a managed web surface, desktop wrapper, or customer-hosted service without changing the normalized evidence model.
- SQLite becomes justified when querying volume, retention, concurrent writers, or policy joins exceed JSONL. Kafka, Kubernetes, a graph database, and a hosted telemetry pipeline are deliberately deferred.

## Reused patterns

- Board Steward: tracker truth and hygiene stay separate from runtime claims.
- Runtime Witness: current machine evidence, exact source, narrow verdict, and named uncertainty.
- TicketBoard MCP: Markdown remains source of record and writes rebuild a derived index.
- vault-rag: explicit local health endpoints and sensitivity-aware boundaries.
- Prometheus/Stormbreaker MCP bridge: read-only probes, short timeouts, no token persistence, summarized responses, and separate future mutation bridge.

## Consequences

The collector must run before the UI to refresh local evidence. A single-machine ledger is not enterprise-tamper-proof. This is acceptable for the commercial validation slice because it makes the trust claim honest and keeps enterprise infrastructure out of the product until customers demonstrate the need.
