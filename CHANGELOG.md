# Changelog

## 0.3.0 — 2026-09-13

Witness is now just the recorder.

- **Split.** The operator UI, local-source adapters, bounded control service, evidence-bundle export, and the product/pilot documents moved out of this repository. What remains is the MCP proxy (stdio and HTTP/SSE), the v0.1 record format, and the CLI (`wrap`, `unwrap`, `verify`, `tail`, `sessions`, `query`, `report`, `anchor`).
- **Zero dependencies.** `npm install` installs nothing. `npm test` runs in seconds with no build step.
- **Publishable.** Package renamed to `@darkvector/witness`, `private` removed, `exports` map added so `lib/` modules can be imported by other tools.
- **DCO.** Contributions require a `Signed-off-by` line (see `CONTRIBUTING.md`).
- Docs rewritten to describe only what this package does. `THREAT_MODEL.md` and `PRIVACY.md` now cover the recorder, not the former vertical slice.
- Record format unchanged: still `v: "0.1"`. Records written by 0.2.0 verify with 0.3.0.

## 0.2.0 — 2026-09-12

- MCP stdio proxy recorder with the v0.1 record schema; `verify`, `tail`, `sessions`.
- `wrap` / `unwrap` for `.mcp.json`, `~/.claude.json`, Cursor, and Claude Desktop configs.
- `query`, `report`, `anchor` (`--git`).
- HTTP / SSE transport: `witness http --upstream <url>`.
- `verify` accepts concatenated exports (one chain per session within a file).
