# Privacy and data handling

The MVP is local-only. It has no product telemetry, hosted account, cloud database, or background upload. Collection reads ticket metadata plus allow-listed health and inventory fields from known local endpoints.

## Never collected

- API keys, bearer tokens, cookies, passwords, authorization headers, or credential values
- prompt bodies, retrieved document bodies, customer records, or generated media
- full source responses when a small status summary is sufficient
- environment-variable values

The collector rejects secret-bearing key names recursively and writes the ledger with user-only filesystem permissions. Sample data is synthetic and must not be generated from private customer records.

## Collected in this slice

- component names and types
- local ticket ids, statuses, and counts for this product
- endpoint reachability and allow-listed runtime versions/device counts
- source timestamps, failure summaries, evidence ids, and hash-chain values
- policy posture and registry-backed approval references

Infrastructure names and model identifiers may still be sensitive. Enterprise deployments need configurable pseudonymization, retention, access controls, export/delete policy, and customer-managed encryption before production use.
