import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { buildEvidenceExport } from "../scripts/export-evidence.mjs";

test("creates a verified export without raw secret-bearing fields", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "dvc-evidence-export-"));
  const output = path.join(directory, "bundle.json");
  try {
    const { bundle } = await buildEvidenceExport({ output });
    assert.equal(bundle.integrity.verified, true);
    assert.ok(bundle.coverage.length >= 4);
    assert.ok(bundle.integrity.eventCount > 0);
    const raw = await readFile(output, "utf8");
    assert.doesNotMatch(raw, /\"(?:token|secret|password|authorization|cookie|api[_-]?key|nonce)\"\s*:/i);
  } finally { await rm(directory, { recursive: true, force: true }); }
});
