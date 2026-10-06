// witness keygen: ed25519 key pairs under $WITNESS_HOME/keys. See SPEC-0.2.md section 2.
// The signer and the plain public key loader live in judge.mjs (keySigner, publicKeyLoader). This file reuses them.
import { createHash, createPublicKey, generateKeyPairSync } from "node:crypto";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { publicKeyLoader } from "./judge.mjs";
import { witnessHome } from "./session-log.mjs";

/** The key_id format: "k_" and 8 lowercase hex characters. */
export const KEY_ID_PATTERN = /^k_[0-9a-f]{8}$/;

export function keysDir(home = witnessHome()) {
  return path.join(home, "keys");
}

/** key_id = "k_" + the first 8 hex characters of sha256(SPKI DER of the public key). Takes a KeyObject or a PEM. */
export function keyIdOf(key) {
  const publicKey = key?.type === "public" ? key : createPublicKey(key);
  const der = publicKey.export({ type: "spki", format: "der" });
  return `k_${createHash("sha256").update(der).digest("hex").slice(0, 8)}`;
}

/**
 * Write one key pair to keys/<key_id>.key (PKCS8 PEM) and keys/<key_id>.pub (SPKI PEM).
 * Files are 0600 and the directory is 0700. An existing file is never overwritten: the call throws and writes nothing.
 */
export function writeKeyPair({ publicKey, privateKey }, home = witnessHome()) {
  const keyId = keyIdOf(publicKey);
  const dir = keysDir(home);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const keyFile = path.join(dir, `${keyId}.key`);
  const pubFile = path.join(dir, `${keyId}.pub`);
  const create = (file, text) => {
    try {
      writeFileSync(file, text, { mode: 0o600, flag: "wx" });
    } catch (error) {
      if (error.code === "EEXIST") throw new Error(`${file} exists; keygen never overwrites a key`);
      throw error;
    }
  };
  create(keyFile, privateKey.export({ type: "pkcs8", format: "pem" }));
  try {
    create(pubFile, publicKey.export({ type: "spki", format: "pem" }));
  } catch (error) {
    // This call made the .key file a moment ago, so it removes it again: a .key without its .pub is not left behind.
    rmSync(keyFile, { force: true });
    throw error;
  }
  return { keyId, keyFile, pubFile };
}

/** Make a new ed25519 key pair in keys/. Returns { keyId, keyFile, pubFile }. */
export function keygen(home = witnessHome()) {
  return writeKeyPair(generateKeyPairSync("ed25519"), home);
}

/**
 * Check that keys/<key_id>.pub is a trusted key for key_id.
 * Returns { pem, problem }. pem is set only when the file exists, holds an ed25519 public key, and that key hashes to key_id.
 */
export function trustedKey(keyId, home = witnessHome()) {
  if (typeof keyId !== "string" || !KEY_ID_PATTERN.test(keyId)) return { pem: null, problem: `invalid key_id ${JSON.stringify(keyId)}` };
  const pem = publicKeyLoader(home)(keyId);
  if (!pem) return { pem: null, problem: `no public key for ${keyId} in ${keysDir(home)}` };
  let key;
  try {
    key = createPublicKey(pem);
  } catch {
    return { pem: null, problem: `keys/${keyId}.pub is not a public key` };
  }
  if (key.asymmetricKeyType !== "ed25519") return { pem: null, problem: `keys/${keyId}.pub is not an ed25519 key` };
  const actual = keyIdOf(key);
  if (actual !== keyId) return { pem: null, problem: `keys/${keyId}.pub holds key ${actual}, not ${keyId}` };
  return { pem, problem: null };
}

/** A public key loader for signed feed chains: key_id -> PEM, or null when trustedKey finds a problem. */
export function trustedKeyLoader(home = witnessHome()) {
  return (keyId) => trustedKey(keyId, home).pem;
}
