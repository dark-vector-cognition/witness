# MVP truth ledger

## Real

- TicketBoard ingestion reads the live local Markdown ticket store.
- vault-rag ingestion calls its live localhost health endpoint.
- Stormbreaker ingestion calls the existing read-only ComfyUI system-stats surface over the established local network path.
- Events append to a local JSONL ledger and are SHA-256 chained.
- The operator UI renders the current generated snapshot and retains source failures.
- Automated tests verify rendering, source count, secret-key exclusion, control mode, and the full ledger hash chain.
- Every adapter now declares its discovery envelope and a coverage verdict, including known limitations.
- The loopback-only control service creates one recorder-owned disposable test agent. Suspend, resume, and terminate use durable, expiring, single-use approvals and independently checked process-state receipts.

## Simulated

- Replay remains evidence-only and does not re-run side effects.
- Local operator identity is derived from the configured local operator id. It is durable evidence, but not enterprise authentication or separation of duties.

## Deferred

- cryptographically signed source events, external timestamping, and tamper-resistant storage
- continuous collectors, retention policy, search, multi-machine federation, RBAC/SSO, and enterprise deployment packaging
- reviewed live-control adapters for real agents and vendor-specific capability negotiation
- broad automatic discovery across vendor APIs

## Commercially risky

- coverage claims are adapter-dependent and incomplete discovery can mislead buyers
- a useful universal control vocabulary may break down across vendor runtimes
- pricing by observed component is unvalidated
- customers may require security controls before agreeing to a paid pilot
