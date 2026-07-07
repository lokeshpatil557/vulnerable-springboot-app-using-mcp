/**
 * Secret redaction. The goal is *never* to log or report a raw secret value:
 *   - The audit logger redacts well-known sensitive arg names.
 *   - Finding `message` strings from secret scanners are masked to last-4-only.
 *   - Reports redact inline values like `password=foo` -> `password=****`.
 */

const REDACTED = "[REDACTED]";
const MASKED = "****";

/** JSON-pointer-like paths to redact (Pino-style). */
export const REDACT_PATHS: string[] = [
  "password",
  "passwd",
  "token",
  "secret",
  "apiKey",
  "api_key",
  "apikey",
  "authorization",
  "headers.Authorization",
  "headers.authorization",
  "cookie",
  "set-cookie",
  "credentials",
  "privateKey",
  "private_key",
  "aws_secret_access_key",
  "GITHUB_TOKEN",
  "SLACK_TOKEN",
];

/** Recursively redact an object's sensitive keys. Returns a new object. */
export function redactObject<T>(value: T, paths: string[] = REDACT_PATHS): T {
  return redactRecursive(value, paths, "") as T;
}

function redactRecursive(value: unknown, paths: string[], prefix: string): unknown {
  if (value === null || value === undefined) return value;
  if (Array.isArray(value)) {
    return value.map((v) => redactRecursive(v, paths, prefix));
  }
  if (typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      const fullKey = prefix ? `${prefix}.${k}` : k;
      const isSensitive = paths.some((p) => p === fullKey || p === k);
      if (isSensitive && (typeof v === "string" || typeof v === "number")) {
        out[k] = REDACTED;
      } else {
        out[k] = redactRecursive(v, paths, fullKey);
      }
    }
    return out;
  }
  return value;
}

/** Mask a secret value to its last 4 characters (or all * if shorter). */
export function maskSecret(secret: string | null | undefined): string {
  if (!secret) return "";
  if (secret.length <= 4) return "*".repeat(secret.length);
  return MASKED + secret.slice(-4);
}

/** Redact inline key=value pairs in a free-text message. */
export function redactMessage(message: string): string {
  if (!message) return message;
  let out = message;
  for (const key of ["password", "passwd", "token", "apiKey", "api_key", "secret", "authorization"]) {
    // Match key="value" or key=value (until whitespace, comma, or end).
    const re = new RegExp(`(${key})\\s*[:=]\\s*("[^"]*"|'[^']*'|\\S+)`, "gi");
    out = out.replace(re, (_m, k) => `${k}=${REDACTED}`);
  }
  return out;
}
