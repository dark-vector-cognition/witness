# Evaluator pilot runbook

## Objective

Demonstrate that an operator can understand source coverage, inspect defensible evidence, approve one bounded control, and export the record without learning a vendor-specific agent console.

## First-time setup

An administrator installs Node.js 22 or later and runs `npm install` once in the project folder. No account, hosted service, API key, or cloud database is required for this pilot.

## Operator flow

1. Double-click `Launch Flight Recorder.command`.
2. Confirm that Recorder online appears and review Source health.
3. Read Source coverage manifest. A zero is meaningful only when the verdict says confirmed absent; not configured, unreachable, and unsupported are distinct conditions.
4. Open Suspend under Bounded control plane. Confirm the target says disposable-test-agent.
5. Enter a reason of at least eight characters and issue the two-minute single-use approval.
6. Execute once. Accept success only when the receipt shows `running → suspended`.
7. Repeat with Resume and require `suspended → running` evidence.
8. Use `npm run export:evidence` when an export is needed. Review infrastructure names and local operator identity before sharing the file from `exports/`.

## Acceptance script

- At least two live read-only sources are nominal.
- Every adapter has a declared coverage scope and limitation.
- An arbitrary target id is denied.
- An approval cannot be reused.
- Suspend and resume show independently verified before/after states.
- The evidence ledger and exported bundle verify successfully.
- Stopping the launcher also stops the disposable test process and control service.

## Stop conditions

Do not proceed to customer-connected control if the target is not recorder-owned, source coverage is ambiguous, approval identity is unsuitable for the customer, ledger verification fails, or dependency findings have not been dispositioned by the evaluator’s security owner.
