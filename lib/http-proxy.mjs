// Local HTTP reverse proxy for remote MCP servers (Streamable HTTP and legacy SSE).
// Harness → http://127.0.0.1:<port>/… → upstream. Bodies pass through byte-for-byte; JSON-RPC is parsed on the way past.
import { createServer } from "node:http";
import { randomBytes } from "node:crypto";
import { digestArgs, sha256 } from "./record.mjs";
import { SessionLog } from "./session-log.mjs";

const HOP = new Set(["connection", "keep-alive", "transfer-encoding", "te", "trailer", "upgrade", "proxy-connection", "host", "content-length"]);

function parseJsonRpc(text) {
  try { const v = JSON.parse(text); return Array.isArray(v) ? v : [v]; } catch { return null; }
}

export function startHttpProxy({ upstream, listenHost = "127.0.0.1", listenPort = 0, principal = null, serverName, allowKeys = [], logDir, stderr = process.stderr }) {
  const target = new URL(upstream);
  const session = `s_${randomBytes(4).toString("hex")}`;
  const server = { name: serverName || target.hostname, upstream_sha256: sha256(target.origin + target.pathname), transport: "http" };
  const principalRecord = principal ? { as: principal, source: process.env.WITNESS_AS === principal ? "env" : "flag", verified: false } : { as: null, source: "none", verified: false };
  const log = new SessionLog({ session, dir: logDir, onError: (error) => stderr.write(`[witness] recording disabled: ${error?.message || error}\n`) });
  let actor = { client: "unknown", version: null, protocol: null };
  const pending = new Map();
  const counts = { calls: 0, ok: 0, error: 0, raw: 0, requests: 0 };
  const startedAt = Date.now();

  const recordRequest = (messages) => {
    for (const frame of messages) {
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
      } catch (error) { stderr.write(`[witness] record error (relay unaffected): ${error?.message || error}\n`); }
    }
  };
  const recordResponse = (messages) => {
    for (const frame of messages) {
      try {
        if (frame.id !== undefined && frame.id !== null && pending.has(String(frame.id))) {
          const call = pending.get(String(frame.id)); pending.delete(String(frame.id));
          const isError = Boolean(frame.error) || frame.result?.isError === true;
          const digest = digestArgs(frame.error ?? frame.result ?? null);
          log.append({ event: "tool_result", rpc_id: frame.id, tool: call.tool, call_seq: call.seq, outcome: { status: isError ? "error" : "ok", result_sha256: digest.sha256, result_bytes: digest.bytes, ms: Date.now() - call.at, ...(frame.error ? { code: frame.error.code ?? null } : {}) } });
          counts[isError ? "error" : "ok"] += 1;
        }
      } catch (error) { stderr.write(`[witness] record error (relay unaffected): ${error?.message || error}\n`); }
    }
  };
  /** Incremental SSE parser: feeds `data:` payloads (multi-line joined) to onEvent. Returns a feeder. */
  const sseParser = (onEvent) => {
    let buffer = ""; let data = [];
    return (chunk) => {
      buffer += chunk;
      let idx;
      while ((idx = buffer.indexOf("\n")) !== -1) {
        const line = buffer.slice(0, idx).replace(/\r$/, ""); buffer = buffer.slice(idx + 1);
        if (line === "") { if (data.length) { const messages = parseJsonRpc(data.join("\n")); if (messages) onEvent(messages); else { counts.raw += 1; log.append({ event: "raw", direction: "server→client", line_sha256: sha256(data.join("\n")), bytes: Buffer.byteLength(data.join("\n")) }); } data = []; } }
        else if (line.startsWith("data:")) data.push(line.slice(5).replace(/^ /, ""));
      }
    };
  };

  const httpServer = createServer(async (req, res) => {
    counts.requests += 1;
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const body = Buffer.concat(chunks);
    if (req.method === "POST" && body.length) {
      const messages = parseJsonRpc(body.toString("utf8"));
      if (messages) recordRequest(messages);
      else { counts.raw += 1; log.append({ event: "raw", direction: "client→server", line_sha256: sha256(body), bytes: body.length }); }
    }
    const headers = {};
    for (const [key, value] of Object.entries(req.headers)) if (!HOP.has(key.toLowerCase()) && value !== undefined) headers[key] = Array.isArray(value) ? value.join(", ") : value;
    const url = new URL(req.url, target.origin);
    url.pathname = url.pathname === "/" ? target.pathname : (target.pathname.replace(/\/$/, "") + url.pathname).replace(/\/{2,}/g, "/");
    let upstreamRes;
    try {
      upstreamRes = await fetch(url, { method: req.method, headers, body: ["GET", "HEAD"].includes(req.method) ? undefined : body, redirect: "manual" });
    } catch (error) {
      log.append({ event: "error", message: `upstream unreachable: ${error?.message || error}` });
      res.writeHead(502, { "content-type": "application/json" }); res.end(JSON.stringify({ jsonrpc: "2.0", error: { code: -32000, message: "witness: upstream unreachable" } })); return;
    }
    const resHeaders = {};
    upstreamRes.headers.forEach((value, key) => { if (!HOP.has(key.toLowerCase())) resHeaders[key] = value; });
    res.writeHead(upstreamRes.status, resHeaders);
    const type = (upstreamRes.headers.get("content-type") || "").toLowerCase();
    if (!upstreamRes.body) { res.end(); return; }
    const reader = upstreamRes.body.getReader();
    const decoder = new TextDecoder();
    const feed = type.includes("text/event-stream") ? sseParser(recordResponse) : null;
    let buffered = "";
    try {
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        res.write(Buffer.from(value)); // relay first
        const text = decoder.decode(value, { stream: true });
        if (feed) feed(text); else if (type.includes("json")) buffered += text;
      }
    } catch { /* client or upstream went away; recorded via counts */ }
    if (buffered) { const messages = parseJsonRpc(buffered); if (messages) recordResponse(messages); }
    res.end();
  });

  return new Promise((resolve, reject) => {
    httpServer.on("error", reject);
    httpServer.listen(listenPort, listenHost, () => {
      const address = httpServer.address();
      const local = `http://${listenHost}:${address.port}`;
      log.append({ event: "session_start", actor, principal: principalRecord, server, listen: local });
      const close = () => new Promise((done) => {
        for (const [id, call] of pending) log.append({ event: "tool_result", rpc_id: id, tool: call.tool, call_seq: call.seq, outcome: { status: "unknown", ms: Date.now() - call.at, reason: "proxy stopped before a response arrived" } });
        log.append({ event: "session_end", exit: { code: 0, signal: null }, counts, ms: Date.now() - startedAt, unresolved: pending.size });
        httpServer.close(() => done());
        httpServer.closeAllConnections?.();
      });
      resolve({ session, file: log.file, local, close, server: httpServer });
    });
  });
}
