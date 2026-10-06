# Privacy and data handling

Witness has no product telemetry, hosted account, cloud database, or background upload. It writes only under `WITNESS_HOME` (default `~/.witness`): the per-session logs in `log/`, a checkpoints file when you run `anchor`, judgment chains in `judge/`, keys in `keys/`, and feed chains in `feed/`.

Witness is local-only, with two exceptions. Each exception happens only when you run its command.

## Exception 1: `witness judge` sends session metadata to the model vendor you pick

- `--vendor anthropic` (the default) sends to `https://api.anthropic.com/v1/messages`. `--vendor openrouter` sends to `https://openrouter.ai/api/v1/chat/completions`.
- What it sends: every record of one session chain, with every `args_summary` removed. That is tool names, argument and result digests and sizes, timing, outcome status, the declared principal, the client name and version, and the server name and command digest.
- What it does not send: `args_summary` values, tool arguments, tool results, headers, or environment values. The API key goes only into the request header. It never goes into a record or onto stdout.
- `--vendor ollama` sends to `OLLAMA_HOST` (default `http://127.0.0.1:11434`). That stays on this machine unless you set `OLLAMA_HOST` to another host. `--vendor stub` sends nothing.
- The vendor's own data policy applies to what it receives.

## Exception 2: `witness feed serve` exposes the published feed over HTTP

- It serves `feed/published.jsonl` over plain HTTP, with no authentication and no TLS, on the address you give with `--host`. It never reads through a symbolic link or a hard link, so it cannot serve another file such as a private key. The default is `127.0.0.1`, which only this machine can reach. With any other address, every host that can reach that address can read the feed.
- What it exposes, for each refused call: the indicator kind and digest (`indicator.sha256`), the reason text (at most 240 characters, written by the council), `origin.host_sha256`, `origin.session`, the timestamp, and the signer's `key_id` and signature.
- `origin.host_sha256` is a plain sha256 of the host name. Anyone can recover a host name that is easy to guess from its digest. The same is true for an indicator digest of a short or common value, such as a domain or a tool name.
- A reason is free text. Read `feed/published.jsonl` before you serve it.
- `witness feed publish` copies only the fields above into `feed/published.jsonl`. Nothing else from the local feed or from a session goes into it.

`witness feed pull <url>` sends exactly one HTTP GET each time you run it. It sends no record.

- The request goes to the URL you give. Witness removes any `user:password@` and any `#fragment` from it first, so no credentials go out.
- If this home already holds a copy from that URL (the URL is in `feed/remote/peers.json`), the query also carries `after=<last seq of the copy>`. Any other URL gets no `after`, and the peer sends its whole feed.
- The request has no body and no cookie. It carries the default headers of the Node.js `fetch`: `accept`, `accept-language`, `accept-encoding`, `sec-fetch-mode` and `user-agent: node`.
- Pull follows no redirect. A redirect stops the pull with exit 1, and no second request goes out.
- The peer sees your IP address, the time of the request, and the `after` number. The `after` number tells the peer how much of its feed you already hold.

Pull stores the peer's signed records in `feed/remote/<key_id>.jsonl` and the URL in `feed/remote/peers.json`.

`keys/<key_id>.key` never leaves the machine. Witness never sends a `.pub` file anywhere. You give your `.pub` to a peer yourself.

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

Tool names, server names, principals, hostnames in the command-line digest, call timing, and payload sizes are metadata, and metadata can be sensitive. The same is true for the feed files and for the remote copies of peer feeds. Treat the log directory as confidential; it is created `0700` with `0600` files for that reason. Review a `report` or an exported log before sharing it outside the machine it was written on.

## Retention

Witness never deletes or rotates its own records. Retention is the operator's decision; deleting a session file removes that session's chain and is detectable against a checkpoint if one was anchored.
