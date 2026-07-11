import { spawn } from "node:child_process";

const control = spawn(process.execPath, ["scripts/control-service.mjs"], { stdio: "inherit" });
const site = spawn(process.platform === "win32" ? "npx.cmd" : "npx", ["vinext", "dev"], { stdio: "inherit", env: { ...process.env, WRANGLER_LOG_PATH: ".wrangler/wrangler.log" } });

let stopping = false;
async function stop(code = 0) {
  if (stopping) return;
  stopping = true;
  control.kill("SIGTERM");
  site.kill("SIGTERM");
  setTimeout(() => process.exit(code), 250).unref();
}

control.once("exit", (code) => stop(code || 0));
site.once("exit", (code) => stop(code || 0));
process.on("SIGINT", () => stop(0));
process.on("SIGTERM", () => stop(0));
