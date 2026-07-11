# MVP truth ledger

## Real

- TicketBoard ingestion reads the live local Markdown ticket store.
- vault-rag ingestion calls its live localhost health endpoint.
- Stormbreaker ingestion calls the existing read-only ComfyUI system-stats surface over the established local network path.
- Events append to a local JSONL ledger and are SHA-256 chained.
- The operator UI renders the current generated snapshot and retains source failures.
- Automated tests verify rendering, source count, secret-key exclusion, control mode, and the full ledger hash chain.

## Simulated

- Replay, suspend, and terminate create an in-browser simulation receipt only. They do not contact or mutate a process.
- Approval is a demonstration checkbox, not authenticated enterprise identity or separation of duties.

## Deferred

- cryptographically signed source events, external timestamping, and tamper-resistant storage
- continuous collectors, retention policy, search, multi-machine federation, RBAC/SSO, and enterprise deployment packaging
- reviewed live-control adapters and target-specific capability negotiation
- broad automatic discovery across vendor APIs

## Commercially risky

- coverage claims are adapter-dependent and incomplete discovery can mislead buyers
- a useful universal control vocabulary may break down across vendor runtimes
- pricing by observed component is unvalidated
- customers may require security controls before agreeing to a paid pilot
