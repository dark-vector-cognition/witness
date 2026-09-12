// Append-only, hash-chained per-session JSONL writer. Logging failures never propagate to the relay.
import { appendFileSync, existsSync, mkdirSync, readFileSync, readdirSync, statSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { GENESIS, SCHEMA_VERSION, sealRecord } from "./record.mjs";

export function witnessHome() {
  return process.env.WITNESS_HOME || path.join(os.homedir(), ".witness");
}

export function logDir(home = witnessHome()) {
  return path.join(home, "log");
}

export function readRecords(file) {
  if (!existsSync(file)) return [];
  return readFileSync(file, "utf8").split("\n").filter(Boolean).map((line) => JSON.parse(line));
}

export function listSessionFiles(dir = logDir()) {
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((name) => name.endsWith(".jsonl"))
    .map((name) => path.join(dir, name))
    .sort((a, b) => statSync(a).mtimeMs - statSync(b).mtimeMs);
}

export class SessionLog {
  constructor({ session, dir = logDir(), onError = () => {} }) {
    this.session = session;
    this.file = path.join(dir, `${session}.jsonl`);
    this.prev = GENESIS;
    this.seq = 0;
    this.onError = onError;
    this.disabled = false;
    try {
      mkdirSync(dir, { recursive: true, mode: 0o700 });
    } catch (error) {
      this.disabled = true;
      this.onError(error);
    }
  }

  append(event) {
    if (this.disabled) return null;
    try {
      const record = sealRecord({ v: SCHEMA_VERSION, seq: this.seq, ts: new Date().toISOString(), session: this.session, ...event }, this.prev);
      appendFileSync(this.file, `${JSON.stringify(record)}\n`, { mode: 0o600 });
      this.prev = record.hash;
      this.seq += 1;
      return record;
    } catch (error) {
      this.disabled = true;
      this.onError(error);
      return null;
    }
  }
}
