import { createHash } from "crypto";

/**
 * Hashes the EXACT raw bytes as uploaded. Do not normalize whitespace,
 * convert line endings, or parse first — the hash must represent the
 * original evidence untouched, per the forensic chain-of-custody
 * requirement (Batch 1 / Batch 6).
 */
export function sha256(buffer: Buffer): string {
  return createHash("sha256").update(buffer).digest("hex");
}
