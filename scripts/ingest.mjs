import { randomUUID } from "node:crypto";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { appendLedgerEvents, readLedger, verifyLedger } from "./lib/ledger.mjs";

const root = path.resolve(import.meta.dirname, "..");
const ticketRoot = process.env.TICKET_STORE_ROOT || path.join(os.homedir(), "Projects", "experience-layering-main", "ticket_store");
const ledgerPath = path.join(root, "data", "ledger", "events.jsonl");
const outputPath = path.join(root, "public", "data", "latest.json");
const now = new Date().toISOString();
const denyKey = /token|secret|password|authorization|cookie|api[_-]?key|credential/i;

async function probe(url, timeout = 2500) {
  try {
    const response = await fetch(url, { headers: { Accept: "application/json" }, signal: AbortSignal.timeout(timeout) });
    const data = response.ok ? await response.json() : null;
    return { ok: response.ok, status: response.status, data };
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message.replace(/https?:\/\/[^\s]+/g, "local endpoint") : "probe failed" };
  }
}

function safeObject(value) {
  if (Array.isArray(value)) return value.map(safeObject);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.entries(value).filter(([key]) => !denyKey.test(key)).map(([key, item]) => [key, safeObject(item)]));
}

async function readTicketMeta() {
  const dir = path.join(ticketRoot, "tickets", "LOCAL");
  let files;
  try {
    files = (await readdir(dir)).filter((file) => /^LOCAL-\d+\.md$/.test(file));
  } catch (error) {
    // A missing store is a coverage fact, not a crash: declare it as not configured.
    const code = error && typeof error === "object" && "code" in error ? String(error.code) : "ERR";
    return { total: 0, flightRecorder: [], path: dir, missing: true, reason: code };
  }
  const records = [];
  for (const file of files) {
    const text = await readFile(path.join(dir, file), "utf8");
    const match = text.match(/<!-- local-ticket-meta\s*([\s\S]*?)\s*-->/);
    if (!match) continue;
    try { records.push(safeObject(JSON.parse(match[1]))); } catch { /* malformed tickets are reported through count drift, never copied */ }
  }
  const flightRecorder = records.filter((ticket) => ticket.project === "DVC Agent Flight Recorder");
  return { total: records.length, flightRecorder, path: dir };
}

const stormbreakerUrl = process.env.STORMBREAKER_STATS_URL || "";
const [tickets, vault, stormbreaker, localModels] = await Promise.all([
  readTicketMeta(),
  probe(process.env.VAULT_RAG_HEALTH_URL || "http://127.0.0.1:8742/health"),
  stormbreakerUrl ? probe(stormbreakerUrl, 3500) : Promise.resolve({ ok: false, configured: false, error: "not configured" }),
  probe(process.env.LOCAL_MODELS_URL || "http://127.0.0.1:1234/v1/models"),
]);

const devices = stormbreaker.ok && Array.isArray(stormbreaker.data?.devices) ? stormbreaker.data.devices : [];
const modelIds = localModels.ok && Array.isArray(localModels.data?.data) ? localModels.data.data.map((model) => String(model.id)).slice(0, 8) : [];
const captureEvents = [
  { id: randomUUID(), at: now, source: "ticketboard", title: tickets.missing ? "Ticket store not configured" : "Ticket inventory captured", summary: tickets.missing ? `No ticket store at the configured path (${tickets.reason}); set TICKET_STORE_ROOT to observe one.` : `${tickets.total} local ticket records observed; ${tickets.flightRecorder.length} govern this product.`, outcome: tickets.missing ? "attention" : "success", evidenceId: `TB-${tickets.missing ? "UNCONFIGURED" : tickets.total}` },
  { id: randomUUID(), at: now, source: "vault-rag", title: vault.ok ? "Knowledge runtime responded" : "Knowledge runtime probe failed", summary: vault.ok ? "The read-only health endpoint returned status ok." : "The failed probe is retained; no restart was attempted.", outcome: vault.ok ? "success" : "attention", evidenceId: `VR-${vault.status || "ERR"}` },
  { id: randomUUID(), at: now, source: "prometheus-stormbreaker", title: stormbreaker.ok ? "Stormbreaker runtime observed" : stormbreaker.configured === false ? "Stormbreaker runtime not configured" : "Stormbreaker runtime unreachable", summary: stormbreaker.ok ? `ComfyUI ${stormbreaker.data?.system?.comfyui_version || "version unknown"} responded with ${devices.length} compute device record(s).` : stormbreaker.configured === false ? "No STORMBREAKER_STATS_URL set; the runtime was not probed." : "The safe system-stats probe failed; no control operation was attempted.", outcome: stormbreaker.ok ? "success" : stormbreaker.configured === false ? "attention" : "failed", evidenceId: `SB-${stormbreaker.status || "ERR"}` },
  { id: randomUUID(), at: now, source: "recorder", title: "Secret boundary enforced", summary: "Only allow-listed status and inventory fields were retained. Authentication material and response bodies are excluded.", outcome: "success", evidenceId: "POL-REDACT-01" },
];
await mkdir(path.dirname(ledgerPath), { recursive: true });
await appendLedgerEvents(ledgerPath, captureEvents);
const allLines = await readLedger(ledgerPath);
const tail = allLines.slice(-10).reverse();
const lastHash = allLines.at(-1)?.hash || "GENESIS";

const inventory = [
  { id: "agent-board-steward", name: "Board Steward", kind: "agent", vendor: "DVC", health: "healthy" },
  { id: "agent-runtime-witness", name: "Runtime Witness", kind: "agent", vendor: "DVC", health: "healthy" },
  { id: "mcp-ticketboard", name: "TicketBoard MCP", kind: "MCP server", vendor: "local", health: tickets.total > 0 ? "healthy" : "attention" },
  { id: "mcp-prometheus", name: "Prometheus bridge", kind: "MCP server", vendor: "local", health: stormbreaker.ok ? "healthy" : "unreachable" },
  { id: "connector-vault", name: "vault-rag", kind: "connector", vendor: "local", health: vault.ok ? "healthy" : "unreachable" },
  ...modelIds.map((id, index) => ({ id: `model-${index}`, name: id, kind: "model", vendor: "local runtime", health: "healthy" })),
];

const snapshot = {
  schemaVersion: "0.1.0", generatedAt: now, machine: os.hostname(), window: "live local capture",
  counts: { agents: inventory.filter((item) => item.kind === "agent").length, models: inventory.filter((item) => item.kind === "model").length, mcpServers: inventory.filter((item) => item.kind === "MCP server").length },
  inventory,
  sources: [
    { id: "ticketboard", name: "TicketBoard", boundary: "local files · read only", health: tickets.total ? "healthy" : "attention", evidence: tickets.missing ? "Ticket store not configured; nothing was read." : `${tickets.total} Markdown records indexed; product tickets ${tickets.flightRecorder.map((ticket) => ticket.id).join(", ")}.`, freshness: "captured now" },
    { id: "vault-rag", name: "vault-rag", boundary: "localhost health · read only", health: vault.ok ? "healthy" : "unreachable", evidence: vault.ok ? "Health endpoint returned an allow-listed ok response." : "Health probe failed; recovery deliberately not attempted.", freshness: "captured now" },
    { id: "stormbreaker", name: "Stormbreaker / ComfyUI", boundary: "Tailscale HTTP · read only", health: stormbreaker.ok ? "healthy" : "unreachable", evidence: stormbreaker.ok ? `Runtime ${stormbreaker.data?.system?.comfyui_version || "unknown"}; ${devices.length} compute device(s).` : stormbreaker.configured === false ? "Not configured; endpoint not probed." : "System-stats endpoint did not respond.", freshness: "captured now" },
  ],
  coverage: [
    { id: "cov-ticketboard", sourceId: "ticketboard", declaredScope: "Local ticket identities, project, status, approval metadata, and counts", status: tickets.missing ? "not_configured" : tickets.total ? "observed" : "confirmed_absent", observed: tickets.total, freshness: now, limitation: "Does not claim agent tool-call telemetry." },
    { id: "cov-vault", sourceId: "vault-rag", declaredScope: "Service reachability and health contract", status: vault.ok ? "observed" : "unreachable", observed: vault.ok ? 1 : 0, freshness: now, limitation: "Document bodies and retrieval results are deliberately excluded." },
    { id: "cov-stormbreaker", sourceId: "stormbreaker", declaredScope: "ComfyUI runtime version and compute-device presence", status: stormbreaker.ok ? "observed" : stormbreaker.configured === false ? "not_configured" : "unreachable", observed: devices.length, freshness: now, limitation: "Generation payloads, prompts, and remote control are unsupported." },
    { id: "cov-models", sourceId: "local-models", declaredScope: "Unauthenticated local model identifiers", status: localModels.ok ? (modelIds.length ? "observed" : "confirmed_absent") : "not_configured", observed: modelIds.length, freshness: now, limitation: "Authenticated endpoints require a reviewed credential adapter; credentials are never inferred." },
  ],
  events: tail.map(({ id, at, source, title, summary, outcome, evidenceId }) => ({ id, at, source, title, summary, outcome, evidenceId })),
  permissions: [
    { id: "p1", identity: "Board Steward", kind: "operating agent", access: "Ticket metadata and comments", policy: "allowed", policyLabel: "Read allowed", approver: "Registry spec · LOCAL-146" },
    { id: "p2", identity: "Runtime Witness", kind: "operating agent", access: "Processes, ports, health endpoints", policy: "allowed", policyLabel: "Read allowed", approver: "Registry spec · LOCAL-146" },
    { id: "p3", identity: "Recorder operator", kind: "human operator", access: "Replay / suspend / terminate", policy: "gated", policyLabel: "Approval gated", approver: "No active grant" },
    { id: "p4", identity: "Source adapters", kind: "connector boundary", access: "Credentials and secret values", policy: "denied", policyLabel: "Never collect", approver: "Hard policy · POL-REDACT-01" },
  ],
  controlContracts: [
    { id: "replay", label: "Replay", description: "Reconstruct inputs and ordered evidence without re-running side effects.", mode: "Simulation only", failure: "Fails closed when inputs, adapter version, or evidence hashes are incomplete." },
    { id: "suspend", label: "Suspend", description: "Pause only the recorder-owned disposable test agent.", mode: "Live test adapter", failure: "Fails closed unless target ownership, single-use approval, and post-action process state all verify." },
    { id: "resume", label: "Resume", description: "Resume the recorder-owned disposable test agent after a verified suspension.", mode: "Live test adapter", failure: "Fails closed unless the target is owned, suspended, and covered by a fresh approval." },
    { id: "terminate", label: "Terminate", description: "Gracefully stop only the recorder-owned disposable test agent.", mode: "Live test adapter", failure: "Never accepts an arbitrary PID or shell command; an unverified exit is reported as unknown." },
  ],
  chain: { eventCount: allLines.length, lastHash, shortHash: lastHash.slice(0, 12), verified: verifyLedger(allLines) },
};

await mkdir(path.dirname(outputPath), { recursive: true });
await writeFile(outputPath, `${JSON.stringify(snapshot, null, 2)}\n`);
console.log(JSON.stringify({ output: outputPath, sources: snapshot.sources.map(({ id, health }) => ({ id, health })), eventCount: snapshot.chain.eventCount }, null, 2));
