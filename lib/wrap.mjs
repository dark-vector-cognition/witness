// witness wrap / unwrap — rewrite MCP config entries to run through the recorder. Reversible; a .bak is kept.
import { copyFileSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const BIN = fileURLToPath(new URL("../bin/witness.mjs", import.meta.url));

/** Known harness config locations, most specific first. */
export function candidateConfigs(cwd = process.cwd()) {
  const home = os.homedir();
  const list = [
    { harness: "Claude Code (project)", file: path.join(cwd, ".mcp.json"), key: "mcpServers" },
    { harness: "Claude Code (user)", file: path.join(home, ".claude.json"), key: "mcpServers" },
    { harness: "Cursor", file: path.join(home, ".cursor", "mcp.json"), key: "mcpServers" },
    { harness: "Claude Desktop", file: process.platform === "darwin" ? path.join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json") : process.platform === "win32" ? path.join(process.env.APPDATA || "", "Claude", "claude_desktop_config.json") : path.join(home, ".config", "Claude", "claude_desktop_config.json"), key: "mcpServers" },
  ];
  return list.filter((c) => existsSync(c.file));
}

export function isWrapped(entry) {
  return Array.isArray(entry?.args) && entry.args.some((a) => typeof a === "string" && a.endsWith(path.join("bin", "witness.mjs"))) && entry.args.includes("--");
}

export function wrapEntry(name, entry, { principal, node = process.execPath, bin = BIN } = {}) {
  if (isWrapped(entry)) return { entry, changed: false };
  if (!entry?.command) return { entry, changed: false, skipped: "no command (remote/HTTP server?)" };
  const args = [bin, "--name", name];
  if (principal) args.push("--as", principal);
  args.push("--", entry.command, ...(entry.args || []));
  return { entry: { ...entry, command: node, args }, changed: true };
}

export function unwrapEntry(entry) {
  if (!isWrapped(entry)) return { entry, changed: false };
  const sep = entry.args.indexOf("--");
  const [command, ...args] = entry.args.slice(sep + 1);
  const restored = { ...entry, command, args };
  if (args.length === 0) delete restored.args;
  return { entry: restored, changed: true };
}

export function rewriteConfig(file, { mode, principal, key = "mcpServers", dryRun = false, node, bin }) {
  const raw = readFileSync(file, "utf8");
  const config = JSON.parse(raw);
  const servers = config[key];
  if (!servers || typeof servers !== "object") return { file, changes: [], skipped: [], note: `no "${key}" object in ${file}` };
  const changes = [];
  const skipped = [];
  for (const [name, entry] of Object.entries(servers)) {
    const result = mode === "wrap" ? wrapEntry(name, entry, { principal, node, bin }) : unwrapEntry(entry);
    if (result.skipped) skipped.push({ name, reason: result.skipped });
    if (result.changed) { servers[name] = result.entry; changes.push(name); }
  }
  if (changes.length && !dryRun) {
    const backup = `${file}.witness-bak`;
    if (!existsSync(backup)) copyFileSync(file, backup);
    const indent = /\n {4}"/.test(raw) ? 4 : 2;
    writeFileSync(file, `${JSON.stringify(config, null, indent)}\n`);
  }
  return { file, changes, skipped, dryRun };
}
