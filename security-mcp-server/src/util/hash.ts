import { createHash } from "node:crypto";

/** Stable hex SHA-256 of a string. */
export function sha256Hex(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}

/** First N characters of the hex digest; used for short, stable fingerprints. */
export function shortHash(input: string, length = 16): string {
  return sha256Hex(input).slice(0, length);
}
