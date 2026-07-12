import { createHash, randomBytes, randomUUID } from "node:crypto";
import { execFile } from "node:child_process";
import { appendFile, mkdir, readFile } from "node:fs/promises";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { appendLedgerEvents } from "./lib/ledger.mjs";

const execFileAsync = promisify(execFile);
const allowedActions = new Set(["suspend", "resume", "terminate"]);
const allowedOrigins = new Set(["http://localhost:3000", "http://127.0.0.1:3000"]);

async function appendJsonl(file, value) {
  await mkdir(path.dirname(file), { recursive: true });
  await appendFile(file, `${JSON.stringify(value)}\n`, { mode: 0o600 });
}

async function readJsonl(file) {
  try { return (await readFile(file, "utf8")).trim().split("\n").filter(Boolean).map((line) => JSON.parse(line)); }
  catch (error) { if (error?.code === "ENOENT") return []; throw error; }
}

function json(response, status, body, origin) {
  response.writeHead(status, {
    "Content-Type": "application/json",
    "Cache-Control": "no-store",
    "Access-Control-Allow-Origin": origin && allowedOrigins.has(origin) ? origin : "http://localhost:3000",
    Vary: "Origin",
  });
  response.end(JSON.stringify(body));
}

async function bodyJson(request) {
  let raw = "";
  for await (const chunk of request) {
    raw += chunk;
    if (raw.length > 16_384) throw new Error("request too large");
  }
  return JSON.parse(raw || "{}");
}

async function processState(pid, exited) {
  if (exited) return "terminated";
  try {
    const { stdout } = await execFileAsync("/bin/ps", ["-o", "state=", "-p", String(pid)]);
    const state = stdout.trim();
    if (!state) return "unknown";
    return state.startsWith("T") ? "suspended" : "running";
  } catch { return "terminated"; }
}

export async function createControlService(options = {}) {
  const root = options.root || path.resolve(import.meta.dirname, "..");
  const dataRoot = options.dataRoot || path.join(root, "data");
  const port = options.port ?? Number(process.env.DVC_CONTROL_PORT || 4317);
  const host = options.host || "127.0.0.1";
  const operator = options.operator || process.env.DVC_OPERATOR_ID || `${os.userInfo().username}@${os.hostname()}`;
  const approvalTtlMs = options.approvalTtlMs ?? 120_000;
  const approvalsPath = path.join(dataRoot, "control", "approvals.jsonl");
  const receiptsPath = path.join(dataRoot, "control", "receipts.jsonl");
  const ledgerPath = path.join(dataRoot, "ledger", "events.jsonl");
  const targetId = `test-agent-${randomUUID()}`;
  const child = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], { stdio: "ignore" });
  let exited = false;
  child.once("exit", () => { exited = true; });
  const issued = new Map();
  const used = new Set((await readJsonl(receiptsPath)).map((receipt) => receipt.approvalId).filter(Boolean));

  await appendLedgerEvents(ledgerPath, [{ id: randomUUID(), at: new Date().toISOString(), source: "control-service", title: "Disposable test agent started", summary: "Recorder-owned test target created for bounded control verification.", outcome: "success", evidenceId: `CTL-TARGET-${targetId.slice(-8)}` }]);

  async function recordAttempt({ approvalId = null, action, outcome, summary, beforeState = null, afterState = null }) {
    const receipt = { receiptId: `RCP-${randomUUID()}`, approvalId, action, targetId, operator, at: new Date().toISOString(), outcome, beforeState, afterState, summary };
    await appendJsonl(receiptsPath, receipt);
    if (approvalId) used.add(approvalId);
    await appendLedgerEvents(ledgerPath, [{ id: randomUUID(), at: receipt.at, source: "control-service", title: `${action} ${outcome}`, summary, outcome: outcome === "success" ? "success" : "failed", evidenceId: receipt.receiptId }]);
    return receipt;
  }

  const server = http.createServer(async (request, response) => {
    const origin = request.headers.origin;
    if (request.method === "OPTIONS") {
      response.writeHead(204, { "Access-Control-Allow-Origin": origin && allowedOrigins.has(origin) ? origin : "http://localhost:3000", "Access-Control-Allow-Headers": "Content-Type", "Access-Control-Allow-Methods": "GET,POST,OPTIONS", Vary: "Origin" });
      return response.end();
    }
    if (origin && !allowedOrigins.has(origin)) return json(response, 403, { error: "origin denied" }, origin);
    try {
      if (request.method === "GET" && request.url === "/status") {
        return json(response, 200, { service: "online", operator, target: { id: targetId, kind: "disposable-test-agent", state: await processState(child.pid, exited) }, capabilities: [...allowedActions] }, origin);
      }
      if (request.method === "POST" && request.url === "/approvals") {
        const body = await bodyJson(request);
        if (body.targetId !== targetId || !allowedActions.has(body.action)) return json(response, 403, { error: "target or action denied" }, origin);
        const reason = String(body.reason || "").trim();
        if (reason.length < 8 || reason.length > 240) return json(response, 400, { error: "reason must be 8-240 characters" }, origin);
        const nonce = randomBytes(24).toString("base64url");
        const issuedAt = new Date();
        const approval = { approvalId: `APR-${randomUUID()}`, operator, targetId, action: body.action, reason, issuedAt: issuedAt.toISOString(), expiresAt: new Date(issuedAt.getTime() + approvalTtlMs).toISOString(), nonceHash: createHash("sha256").update(nonce).digest("hex"), policyResult: "allow_single_use" };
        issued.set(approval.approvalId, approval);
        await appendJsonl(approvalsPath, approval);
        await appendLedgerEvents(ledgerPath, [{ id: randomUUID(), at: approval.issuedAt, source: "control-service", title: `${body.action} approval issued`, summary: `Single-use approval recorded for ${operator}; expires in ${Math.round(approvalTtlMs / 1000)} seconds.`, outcome: "success", evidenceId: approval.approvalId }]);
        return json(response, 201, { approvalId: approval.approvalId, operator, targetId, action: approval.action, issuedAt: approval.issuedAt, expiresAt: approval.expiresAt, nonce }, origin);
      }
      if (request.method === "POST" && request.url === "/controls") {
        const body = await bodyJson(request);
        const approval = issued.get(body.approvalId);
        const beforeState = await processState(child.pid, exited);
        const invalid = !approval || used.has(body.approvalId) || approval.targetId !== targetId || approval.action !== body.action || Date.now() >= Date.parse(approval.expiresAt) || createHash("sha256").update(String(body.nonce || "")).digest("hex") !== approval.nonceHash;
        if (invalid) {
          const receipt = await recordAttempt({ approvalId: body.approvalId, action: String(body.action || "unknown"), outcome: "denied", summary: "Control denied: approval missing, expired, reused, mismatched, or invalid.", beforeState, afterState: beforeState });
          return json(response, 403, receipt, origin);
        }
        if (body.action === "suspend" && beforeState === "running") process.kill(child.pid, "SIGSTOP");
        else if (body.action === "resume" && beforeState === "suspended") process.kill(child.pid, "SIGCONT");
        else if (body.action === "terminate" && beforeState !== "terminated") child.kill("SIGTERM");
        else {
          const receipt = await recordAttempt({ approvalId: approval.approvalId, action: body.action, outcome: "denied", summary: `Control denied from invalid target state ${beforeState}.`, beforeState, afterState: beforeState });
          return json(response, 409, receipt, origin);
        }
        await new Promise((resolve) => setTimeout(resolve, 80));
        const afterState = await processState(child.pid, exited);
        const expected = body.action === "suspend" ? "suspended" : body.action === "resume" ? "running" : "terminated";
        const outcome = afterState === expected ? "success" : "unknown";
        const receipt = await recordAttempt({ approvalId: approval.approvalId, action: body.action, outcome, summary: outcome === "success" ? `${body.action} verified by independent process-state check.` : `${body.action} acknowledgement could not be independently verified.`, beforeState, afterState });
        return json(response, outcome === "success" ? 200 : 503, receipt, origin);
      }
      return json(response, 404, { error: "not found" }, origin);
    } catch (error) {
      return json(response, 500, { error: error instanceof Error ? error.message : "control service failure" }, origin);
    }
  });

  await new Promise((resolve, reject) => { server.once("error", reject); server.listen(port, host, resolve); });
  const address = server.address();
  return {
    port: typeof address === "object" && address ? address.port : port,
    targetId,
    operator,
    close: async () => {
      if (!exited) { try { process.kill(child.pid, "SIGCONT"); child.kill("SIGTERM"); } catch {} }
      await new Promise((resolve) => server.close(resolve));
    },
  };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const service = await createControlService();
  console.log(`DVC control service listening on http://127.0.0.1:${service.port}`);
  const stop = async () => { await service.close(); process.exit(0); };
  process.on("SIGINT", stop);
  process.on("SIGTERM", stop);
}
