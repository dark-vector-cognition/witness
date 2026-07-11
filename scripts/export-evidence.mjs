import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { readLedger, verifyLedger } from "./lib/ledger.mjs";

async function readJsonl(file) {
  try { return (await readFile(file, "utf8")).trim().split("\n").filter(Boolean).map((line) => JSON.parse(line)); }
  catch (error) { if (error?.code === "ENOENT") return []; throw error; }
}

export async function buildEvidenceExport({ root = path.resolve(import.meta.dirname, ".."), output } = {}) {
  const snapshot = JSON.parse(await readFile(path.join(root, "public", "data", "latest.json"), "utf8"));
  const ledger = await readLedger(path.join(root, "data", "ledger", "events.jsonl"));
  const approvals = await readJsonl(path.join(root, "data", "control", "approvals.jsonl"));
  const receipts = await readJsonl(path.join(root, "data", "control", "receipts.jsonl"));
  const generatedAt = new Date().toISOString();
  const bundle = {
    format: "dvc-agent-flight-recorder-evidence",
    version: "0.2.0",
    generatedAt,
    handling: "Operator-created local export. Review infrastructure names and operator identity before sharing.",
    integrity: { algorithm: "SHA-256 hash chain", verified: verifyLedger(ledger), eventCount: ledger.length, lastHash: ledger.at(-1)?.hash || "GENESIS" },
    coverage: snapshot.coverage,
    sources: snapshot.sources,
    inventory: snapshot.inventory,
    approvals,
    receipts,
    events: ledger,
  };
  const target = output || path.join(root, "exports", `flight-recorder-evidence-${generatedAt.replaceAll(":", "-")}.json`);
  await mkdir(path.dirname(target), { recursive: true });
  await writeFile(target, `${JSON.stringify(bundle, null, 2)}\n`, { mode: 0o600 });
  return { target, bundle };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const result = await buildEvidenceExport();
  console.log(`Evidence export written to ${result.target}`);
}
