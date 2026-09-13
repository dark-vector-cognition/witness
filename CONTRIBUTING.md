# Contributing to Witness

Witness is small on purpose: a transparent MCP proxy, a hash-chained record format, and a CLI to verify and read the records. Contributions that keep it small are the ones most likely to land.

## Ground rules

- **Zero runtime dependencies.** `lib/` and `bin/` use only Node built-ins. A pull request that adds a dependency needs a reason the built-ins can't cover.
- **Relay first, record second.** Nothing in the recording path may delay, alter, or drop a frame. A recorder failure writes to stderr and keeps relaying.
- **Digest, don't store.** Arguments and results are hashed. New fields that carry plaintext from a tool call need an explicit allow-list path and a test proving the deny-list still holds.
- **The format is the contract.** Any change to what a record contains bumps `v` in `SPEC.md` and the `SCHEMA_VERSION` constant together, and `witness verify` must still verify records written by every earlier `v`.
- **Every claim in the README is tested.** If it's under "Real today", there's a test for it.

## Developer Certificate of Origin

Every commit must be signed off (`git commit -s`), which adds a `Signed-off-by:` line certifying the [Developer Certificate of Origin 1.1](https://developercertificate.org/). Sign-off means you wrote the change or have the right to submit it under the Apache-2.0 license. Unsigned commits are not merged.

## Running the tests

```bash
npm test          # all suites, no build step, ~6 seconds
```

The suites spawn a fake MCP server (`tests/fixtures/fake-mcp-server.mjs`) and a fake HTTP MCP server, run the real CLI against them, and verify the chains they produce. They write only under a temporary `WITNESS_HOME`.

## Reporting a security issue

Email hello@darkvectorcognition.ai rather than opening a public issue. The threat model is in `docs/THREAT_MODEL.md`; a report that shows the recorder can be made to drop a frame, store a secret, or accept a forged chain gets a same-week response.
