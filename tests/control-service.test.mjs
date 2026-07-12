import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { createControlService } from "../scripts/control-service.mjs";
import { readLedger, verifyLedger } from "../scripts/lib/ledger.mjs";

async function post(base, route, body) {
  const response = await fetch(`${base}${route}`, { method: "POST", headers: { "Content-Type": "application/json", Origin: "http://localhost:3000" }, body: JSON.stringify(body) });
  return { status: response.status, body: await response.json() };
}

test("durable single-use approval controls only the owned disposable agent", async () => {
  const dataRoot = await mkdtemp(path.join(os.tmpdir(), "dvc-flight-recorder-"));
  const service = await createControlService({ dataRoot, port: 0, operator: "test-operator" });
  const base = `http://127.0.0.1:${service.port}`;
  try {
    const status = await (await fetch(`${base}/status`)).json();
    assert.equal(status.target.id, service.targetId);
    assert.equal(status.target.state, "running");
    assert.deepEqual(status.capabilities.sort(), ["resume", "suspend", "terminate"]);

    const wrongTarget = await post(base, "/approvals", { targetId: "arbitrary-pid-1", action: "suspend", reason: "Unauthorized target test" });
    assert.equal(wrongTarget.status, 403);

    const approvedSuspend = await post(base, "/approvals", { targetId: service.targetId, action: "suspend", reason: "Verify bounded suspension" });
    assert.equal(approvedSuspend.status, 201);
    const { approvalId, nonce } = approvedSuspend.body;

    const suspended = await post(base, "/controls", { approvalId, nonce, targetId: service.targetId, action: "suspend" });
    assert.equal(suspended.status, 200);
    assert.equal(suspended.body.afterState, "suspended");

    const replayed = await post(base, "/controls", { approvalId, nonce, targetId: service.targetId, action: "suspend" });
    assert.equal(replayed.status, 403);
    assert.equal(replayed.body.outcome, "denied");

    const approvedResume = await post(base, "/approvals", { targetId: service.targetId, action: "resume", reason: "Return test target to running" });
    const resumed = await post(base, "/controls", { approvalId: approvedResume.body.approvalId, nonce: approvedResume.body.nonce, targetId: service.targetId, action: "resume" });
    assert.equal(resumed.status, 200);
    assert.equal(resumed.body.afterState, "running");

    const approvedTerminate = await post(base, "/approvals", { targetId: service.targetId, action: "terminate", reason: "Complete disposable test run" });
    const terminated = await post(base, "/controls", { approvalId: approvedTerminate.body.approvalId, nonce: approvedTerminate.body.nonce, targetId: service.targetId, action: "terminate" });
    assert.equal(terminated.status, 200);
    assert.equal(terminated.body.afterState, "terminated");

    const approvalsRaw = await readFile(path.join(dataRoot, "control", "approvals.jsonl"), "utf8");
    const receiptsRaw = await readFile(path.join(dataRoot, "control", "receipts.jsonl"), "utf8");
    assert.doesNotMatch(approvalsRaw, new RegExp(nonce.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
    assert.match(approvalsRaw, /nonceHash/);
    assert.match(receiptsRaw, new RegExp(approvalId));
    assert.equal(verifyLedger(await readLedger(path.join(dataRoot, "ledger", "events.jsonl"))), true);
  } finally {
    await service.close();
    await rm(dataRoot, { recursive: true, force: true });
  }
});

test("expired single-use approval is denied and never changes target state", async () => {
  const dataRoot = await mkdtemp(path.join(os.tmpdir(), "dvc-flight-recorder-"));
  const service = await createControlService({ dataRoot, port: 0, operator: "test-operator", approvalTtlMs: 30 });
  const base = `http://127.0.0.1:${service.port}`;
  try {
    const approved = await post(base, "/approvals", { targetId: service.targetId, action: "suspend", reason: "Verify approval expiry window" });
    assert.equal(approved.status, 201);
    const { approvalId, nonce } = approved.body;
    assert.ok(Date.parse(approved.body.expiresAt) > Date.parse(approved.body.issuedAt));

    // Let the 30ms approval window lapse before exercising the control.
    await new Promise((resolve) => setTimeout(resolve, 60));

    const expired = await post(base, "/controls", { approvalId, nonce, targetId: service.targetId, action: "suspend" });
    assert.equal(expired.status, 403);
    assert.equal(expired.body.outcome, "denied");
    assert.equal(expired.body.beforeState, "running");
    assert.equal(expired.body.afterState, "running");

    // Independent re-check: the expired approval never suspended the disposable target.
    const status = await (await fetch(`${base}/status`)).json();
    assert.equal(status.target.state, "running");

    // The denial is recorded as an immutable, verifiable audit event.
    const receiptsRaw = await readFile(path.join(dataRoot, "control", "receipts.jsonl"), "utf8");
    assert.match(receiptsRaw, new RegExp(approvalId));
    assert.equal(verifyLedger(await readLedger(path.join(dataRoot, "ledger", "events.jsonl"))), true);
  } finally {
    await service.close();
    await rm(dataRoot, { recursive: true, force: true });
  }
});
