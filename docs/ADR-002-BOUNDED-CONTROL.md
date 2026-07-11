# ADR-002: separate loopback service for bounded control

Status: accepted for the disposable-agent pilot

## Decision

Keep observation and control in separate runtime boundaries. The operator UI reaches fixed same-origin API routes. Those routes proxy only three fixed operations to a service bound to `127.0.0.1`. The service owns the disposable child process, mints expiring single-use approvals, executes fixed signal operations, independently checks process state, and appends receipts to the evidence ledger.

The service never accepts a PID, executable, filesystem path, signal name, network destination, or shell command from the UI. The target id is unpredictable and maps only to the process created by that service instance.

## Why

- A browser should not receive arbitrary local process authority.
- Hosted or disconnected builds fail closed because no loopback service exists.
- Source adapters remain read-only and cannot accidentally acquire mutation capability.
- Vendor-specific control adapters can later live behind the same approval/receipt contract without weakening the first boundary.

## Limits

The local operator id is evidence, not strong authentication. Unix signals are appropriate only for the disposable test process and do not define universal cross-vendor suspend semantics. Production adapters require reviewed target identity, native acknowledgement, timeouts, rollback behavior, and customer-specific policy.
