# Privacy and data handling

Witness is local-only. It has no product telemetry, hosted account, cloud database, or background upload. Its only output is the per-session log under `WITNESS_HOME` (default `~/.witness`) and, when you run `anchor`, a checkpoints file beside it.

## Never recorded

- tool-call arguments or tool results in plaintext (only their SHA-256 and byte length)
- API keys, bearer tokens, cookies, passwords, authorization headers, or any value under a key matching `token | secret | password | authorization | cookie | api_key | credential`, even when that key is explicitly allow-listed
- HTTP headers, in either direction
- prompt bodies, model responses, retrieved documents, or anything that is not a JSON-RPC frame at the MCP boundary
- server `stderr` (passed through, never written)
- environment-variable values

## Recorded, per session

- session id, start and end timestamps, exit code or signal, counts
- the MCP client's name, version, and protocol version, as it declared them in `initialize`
- the server's name (or command basename) and a SHA-256 of its full command line or upstream origin
- the declared principal (`--as` / `WITNESS_AS`) and how it was supplied
- for every `tools/call`: the tool name, the JSON-RPC id, `args_sha256`, `args_bytes`, and — only for keys you pass with `--allow` — a summary of those values truncated to 120 characters
- for every result: status, latency, `result_sha256`, `result_bytes`, and the JSON-RPC error code if any
- for every notification: its method name
- for every non-JSON line: direction, byte length, and a SHA-256

## What can still be sensitive

Tool names, server names, principals, hostnames in the command-line digest, call timing, and payload sizes are metadata, and metadata can be sensitive. Treat the log directory as confidential; it is created `0700` with `0600` files for that reason. Review a `report` or an exported log before sharing it outside the machine it was written on.

## Retention

Witness never deletes or rotates its own records. Retention is the operator's decision; deleting a session file removes that session's chain and is detectable against a checkpoint if one was anchored.
