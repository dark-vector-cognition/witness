import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";

const file = new URL("../data/ledger/events.jsonl", import.meta.url);
const records = (await readFile(file, "utf8")).trim().split("\n").filter(Boolean).map((line) => JSON.parse(line));
let previous = "GENESIS";
for (const record of records) {
  const { hash, ...payload } = record;
  assert.equal(payload.previousHash, previous, `broken previousHash at ${record.id}`);
  assert.equal(createHash("sha256").update(JSON.stringify(payload)).digest("hex"), hash, `broken hash at ${record.id}`);
  previous = hash;
}
console.log(`Verified ${records.length} append-only evidence events.`);
