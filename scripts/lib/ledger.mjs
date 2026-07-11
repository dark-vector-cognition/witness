import { createHash } from "node:crypto";
import { appendFile, mkdir, readFile } from "node:fs/promises";
import path from "node:path";

export async function readLedger(ledgerPath) {
  try {
    return (await readFile(ledgerPath, "utf8")).trim().split("\n").filter(Boolean).map((line) => JSON.parse(line));
  } catch (error) {
    if (error?.code === "ENOENT") return [];
    throw error;
  }
}

export async function appendLedgerEvents(ledgerPath, events) {
  await mkdir(path.dirname(ledgerPath), { recursive: true });
  const existing = await readLedger(ledgerPath);
  let previousHash = existing.at(-1)?.hash || "GENESIS";
  const appended = [];
  for (const event of events) {
    const payload = { ...event, previousHash };
    const hash = createHash("sha256").update(JSON.stringify(payload)).digest("hex");
    const record = { ...payload, hash };
    await appendFile(ledgerPath, `${JSON.stringify(record)}\n`, { mode: 0o600 });
    appended.push(record);
    previousHash = hash;
  }
  return appended;
}

export function verifyLedger(records) {
  let previousHash = "GENESIS";
  for (const record of records) {
    const { hash, ...payload } = record;
    if (payload.previousHash !== previousHash) return false;
    if (createHash("sha256").update(JSON.stringify(payload)).digest("hex") !== hash) return false;
    previousHash = hash;
  }
  return true;
}
