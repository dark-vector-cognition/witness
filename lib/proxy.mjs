// Transparent stdio relay for MCP servers. Every frame passes through untouched;
// JSON-RPC frames are parsed on the way past and recorded. Parse failure = pass through + raw event.
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import path from "node:path";
import { digestArgs, sha256 } from "./record.mjs";
import { SessionLog } from "./session-log.mjs";

function splitLines(buffer, chunk, onLine) {
  let data = buffer + chunk;
  let index;
  while ((index = data.indexOf("\n")) !== -1) {
    onLine(data.slice(0, index + 1));
    data = data.slice(index + 1);
  }
  return data;
}

function parseFrame(line) {
  const text = line.trim();
  if (!text.startsWith("{")) return null;
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

export function runProxy({ command, args = [], principal, serverName, allowKeys = [], logDir, stdin = process.stdin, stdout = process.stdout, stderr = process.stderr }) {
  const session = `s_${randomBytes(4).toString("hex")}`;
  const cmdLine = [command, ...args].join(" ");
  const server = { name: serverName || path.basename(command), cmd_sha256: sha256(cmdLine) };
  const principalRecord = principal ? { as: principal, source: process.env.WITNESS_AS === principal ? "env" : "flag", verified: false } : { as: null, source: "none", verified: false };
  const log = new SessionLog({ session, dir: logDir, onError: (error) => stderr.write(`[witness] recording disabled: ${error?.message || error}\n`) });
  let actor = { client: "unknown", version: null, protocol: null };
  const pending = new Map();
  const startedAt = Date.now();
  const counts = { calls: 0, ok: 0, error: 0, raw: 0 };

  const child = spawn(command, args, { stdio: ["pipe", "pipe", "inherit"], env: process.env });
  log.append({ event: "session_start", actor, principal: principalRecord, server, pid: child.pid ?? null });

  // A dead pipe on either side must never take the relay down with an unhandled 'error'.
  const quiet = (stream, label) => stream?.on?.("error", (error) => { if (error?.code !== "EPIPE" && error?.code !== "ERR_STREAM_DESTROYED") stderr.write(`[witness] ${label}: ${error?.message || error}\n`); });
  quiet(child.stdin, "server stdin"); quiet(child.stdout, "server stdout"); quiet(stdin, "client stdin"); quiet(stdout, "client stdout");
  const safeWrite = (stream, chunk) => { try { if (stream && !stream.destroyed && stream.writable) stream.write(chunk); } catch { /* relay target gone; recorded via exit */ } };

  let inBuffer = "";
  let outBuffer = "";
  let ended = false;

  const recordClientFrame = (line) => {
    if (ended) return; // the session is sealed; nothing after session_end
    const frame = parseFrame(line);
    if (!frame) { counts.raw += 1; log.append({ event: "raw", direction: "client→server", line_sha256: sha256(line), bytes: Buffer.byteLength(line) }); return; }
    try {
      if (frame.method === "initialize") {
        const info = frame.params?.clientInfo || {};
        actor = { client: info.name || "unknown", version: info.version || null, protocol: frame.params?.protocolVersion || null };
        log.append({ event: "session_client", actor });
      } else if (frame.method === "tools/call") {
        const tool = frame.params?.name || "unknown";
        const digest = digestArgs(frame.params?.arguments, allowKeys);
        const record = log.append({ event: "tool_call", rpc_id: frame.id ?? null, tool, args_sha256: digest.sha256, args_bytes: digest.bytes, ...(digest.summary ? { args_summary: digest.summary } : {}), actor, principal: principalRecord, server });
        if (frame.id !== undefined && frame.id !== null) pending.set(String(frame.id), { tool, at: Date.now(), seq: record?.seq ?? null });
        counts.calls += 1;
      } else if (frame.method && frame.id === undefined) {
        log.append({ event: "notification", direction: "client→server", method: frame.method });
      }
    } catch (error) {
      stderr.write(`[witness] record error (relay unaffected): ${error?.message || error}\n`);
    }
  };

  const recordServerFrame = (line) => {
    if (ended) return;
    const frame = parseFrame(line);
    if (!frame) { counts.raw += 1; log.append({ event: "raw", direction: "server→client", line_sha256: sha256(line), bytes: Buffer.byteLength(line) }); return; }
    try {
      if (frame.id !== undefined && frame.id !== null && pending.has(String(frame.id))) {
        const call = pending.get(String(frame.id));
        pending.delete(String(frame.id));
        const isError = Boolean(frame.error) || frame.result?.isError === true;
        const payload = frame.error ?? frame.result ?? null;
        const digest = digestArgs(payload);
        log.append({ event: "tool_result", rpc_id: frame.id, tool: call.tool, call_seq: call.seq, outcome: { status: isError ? "error" : "ok", result_sha256: digest.sha256, result_bytes: digest.bytes, ms: Date.now() - call.at, ...(frame.error ? { code: frame.error.code ?? null } : {}) } });
        counts[isError ? "error" : "ok"] += 1;
      }
    } catch (error) {
      stderr.write(`[witness] record error (relay unaffected): ${error?.message || error}\n`);
    }
  };

  stdin.on("data", (chunk) => {
    safeWrite(child.stdin, chunk); // relay first, always
    inBuffer = splitLines(inBuffer, chunk.toString("utf8"), recordClientFrame);
  });
  stdin.on("end", () => { try { child.stdin.end(); } catch { /* already closed */ } });
  child.stdout.on("data", (chunk) => {
    safeWrite(stdout, chunk);
    outBuffer = splitLines(outBuffer, chunk.toString("utf8"), recordServerFrame);
  });
  child.on("error", (error) => {
    log.append({ event: "error", message: error?.message || String(error) });
    stderr.write(`[witness] failed to start server: ${error?.message || error}\n`);
    process.exitCode = 1;
  });

  const finish = (code, signal) => {
    if (ended) return;
    // Flush any partial trailing line from the server before sealing.
    if (outBuffer.trim()) { recordServerFrame(outBuffer); outBuffer = ""; }
    for (const [id, call] of pending) log.append({ event: "tool_result", rpc_id: id, tool: call.tool, call_seq: call.seq, outcome: { status: "unknown", ms: Date.now() - call.at, reason: "server exited before responding" } });
    log.append({ event: "session_end", exit: { code: code ?? null, signal: signal ?? null }, counts, ms: Date.now() - startedAt, unresolved: pending.size });
    ended = true;
  };
  // 'close' fires after the server's stdio has fully drained, so every reply has been relayed and recorded.
  child.on("close", (code, signal) => {
    finish(code, signal);
    const exitCode = code ?? (signal ? 1 : 0);
    try { stdin.pause?.(); } catch { /* ignore */ }
    stdout.write("", () => process.exit(exitCode));
  });
  for (const sig of ["SIGINT", "SIGTERM", "SIGHUP"]) process.on(sig, () => { if (!child.killed) child.kill(sig); });
  return { session, file: log.file, child };
}
