import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash, createPublicKey, generateKeyPairSync } from "node:crypto";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { keyIdOf, keygen, trustedKey, writeKeyPair } from "../lib/keys.mjs";

const bin = new URL("../bin/witness.mjs", import.meta.url).pathname;
const tempHome = () => mkdtemp(path.join(os.tmpdir(), "witness-feed-"));

function run(args, env = {}) {
  return new Promise((resolve) => {
    const p = spawn(process.execPath, [bin, ...args], { env: { ...process.env, ...env } });
    let out = ""; let err = "";
    p.stdout.on("data", (c) => { out += c; }); p.stderr.on("data", (c) => { err += c; });
    p.on("exit", (code) => resolve({ code, out, err }));
  });
}

test("keygen: prints k_ + 8 hex of sha256(SPKI DER), writes 0600 files in a 0700 keys/", async () => {
  const home = await tempHome();
  const result = await run(["keygen"], { WITNESS_HOME: home });
  assert.equal(result.code, 0, result.err);
  const keyId = result.out.trim();
  assert.match(keyId, /^k_[0-9a-f]{8}$/);
  const pub = await readFile(path.join(home, "keys", `${keyId}.pub`), "utf8");
  const der = createPublicKey(pub).export({ type: "spki", format: "der" });
  assert.equal(keyId, `k_${createHash("sha256").update(der).digest("hex").slice(0, 8)}`);
  assert.equal(createPublicKey(pub).asymmetricKeyType, "ed25519");
  assert.match(await readFile(path.join(home, "keys", `${keyId}.key`), "utf8"), /BEGIN PRIVATE KEY/);
  assert.equal((await stat(path.join(home, "keys"))).mode & 0o777, 0o700);
  assert.equal((await stat(path.join(home, "keys", `${keyId}.key`))).mode & 0o777, 0o600);
  assert.equal((await stat(path.join(home, "keys", `${keyId}.pub`))).mode & 0o777, 0o600);
  assert.equal(trustedKey(keyId, home).problem, null);
  await rm(home, { recursive: true, force: true });
});

test("keygen: never overwrites a .key or a .pub, and leaves no half pair behind", async () => {
  const home = await tempHome();
  const pair = generateKeyPairSync("ed25519");
  const { keyId, keyFile, pubFile } = writeKeyPair(pair, home);
  assert.equal(keyId, keyIdOf(pair.publicKey));
  const before = await readFile(keyFile, "utf8");
  assert.throws(() => writeKeyPair(pair, home), /exists; keygen never overwrites a key/);
  assert.equal(await readFile(keyFile, "utf8"), before);
  // Only the .pub exists: the call fails and removes the .key it made.
  await rm(keyFile);
  await writeFile(pubFile, "operator copy\n");
  assert.throws(() => writeKeyPair(pair, home), /exists/);
  await assert.rejects(stat(keyFile), { code: "ENOENT" });
  assert.equal(await readFile(pubFile, "utf8"), "operator copy\n");
  // Two runs make two different keys; neither touches the other.
  const a = keygen(home); const b = keygen(home);
  assert.notEqual(a.keyId, b.keyId);
  await rm(home, { recursive: true, force: true });
});

test("keys: a .pub whose content hashes to a different key_id is not trusted", async () => {
  const home = await tempHome();
  const a = keygen(home); const b = keygen(home);
  await writeFile(a.pubFile, await readFile(b.pubFile));
  assert.match(trustedKey(a.keyId, home).problem, new RegExp(`holds key ${b.keyId}, not ${a.keyId}`));
  assert.match(trustedKey("k_00000000", home).problem, /no public key/);
  assert.match(trustedKey("../keys/x", home).problem, /invalid key_id/);
  await rm(home, { recursive: true, force: true });
});
