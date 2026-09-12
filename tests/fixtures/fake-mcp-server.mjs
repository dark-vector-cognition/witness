// Minimal MCP-shaped stdio server: answers initialize, tools/list, tools/call (echo ok; "fail" errors; "hang" never replies).
import readline from "node:readline";
const rl = readline.createInterface({ input: process.stdin });
const send = (obj) => process.stdout.write(`${JSON.stringify(obj)}\n`);
rl.on("line", (line) => {
  if (line.startsWith("#")) { process.stdout.write("# server-side noise line\n"); return; }
  let msg; try { msg = JSON.parse(line); } catch { return; }
  if (msg.method === "initialize") send({ jsonrpc: "2.0", id: msg.id, result: { protocolVersion: msg.params?.protocolVersion, capabilities: { tools: {} }, serverInfo: { name: "fake-server", version: "0.0.1" } } });
  else if (msg.method === "tools/list") send({ jsonrpc: "2.0", id: msg.id, result: { tools: [{ name: "echo" }, { name: "fail" }, { name: "hang" }] } });
  else if (msg.method === "tools/call") {
    const name = msg.params?.name;
    if (name === "hang") return;
    if (name === "fail") send({ jsonrpc: "2.0", id: msg.id, error: { code: -32000, message: "tool failed" } });
    else if (name === "soft-fail") send({ jsonrpc: "2.0", id: msg.id, result: { isError: true, content: [{ type: "text", text: "nope" }] } });
    else send({ jsonrpc: "2.0", id: msg.id, result: { content: [{ type: "text", text: JSON.stringify(msg.params?.arguments ?? {}) }] } });
  }
});
rl.on("close", () => process.exit(0));
