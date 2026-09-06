import { scryptSync, randomBytes, timingSafeEqual } from "crypto";

// Batch 5: uses Node's built-in crypto.scrypt rather than bcrypt, to
// avoid a native-compile dependency for a single hardcoded credential.
// Stored hash format: "<salt-hex>:<hash-hex>".

const KEY_LENGTH = 64;

export function hashPassword(password: string): string {
  const salt = randomBytes(16).toString("hex");
  const hash = scryptSync(password, salt, KEY_LENGTH).toString("hex");
  return `${salt}:${hash}`;
}

export function verifyPassword(password: string, stored: string): boolean {
  const [salt, hashHex] = stored.split(":");
  if (!salt || !hashHex) return false;

  const hash = scryptSync(password, salt, KEY_LENGTH);
  const storedHash = Buffer.from(hashHex, "hex");

  // scryptSync's output length is fixed by KEY_LENGTH, but a hand-edited
  // or truncated env var could still produce a mismatched buffer length
  // here — timingSafeEqual throws on unequal lengths, so this guard
  // turns that into "wrong password" instead of a 500.
  if (hash.length !== storedHash.length) return false;
  return timingSafeEqual(hash, storedHash);
}
