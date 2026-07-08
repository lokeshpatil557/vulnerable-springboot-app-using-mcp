import { mkdir, stat } from "node:fs/promises";
import { dirname, isAbsolute, resolve } from "node:path";
import { pino, type Logger } from "pino";
import { destination as pinoDestination } from "pino";
import type { Config } from "./config.js";

export type AuditOutcome = "ok" | "error" | "unavailable" | "denied";

export interface AuditEvent {
  ts: string;
  tool: string;
  args: unknown;
  findingCount: number;
  durationMs: number;
  outcome: AuditOutcome;
  errorCode: string | null;
  /** Path-safety flag — true when the request did not attempt to escape the repo. */
  pathSafe?: boolean;
  /** Optional per-request correlation id. */
  requestId?: string;
  /** Per-tool actor (e.g. the model session, user id). */
  actor?: string;
}

/** Paths whose values are redacted in audit args before serialization. */
const REDACT_PATHS = [
  "password",
  "token",
  "secret",
  "apiKey",
  "apikey",
  "authorization",
  "headers.Authorization",
  "headers.authorization",
  "cookie",
  "credentials",
  "privateKey",
  "private_key",
];

export interface AuditLogger {
  record(event: AuditEvent): void;
  flush(): Promise<void>;
  readonly path: string;
}

/**
 * Build a JSONL audit logger. Each `record` call appends one line. The
 * destination is `config.auditLogPath`; relative paths are resolved against
 * `config.repoRoot` when it is not "auto".
 */
export async function createAuditLogger(
  config: Config,
  repoRoot: string,
): Promise<AuditLogger> {
  const target = resolveAuditPath(config.auditLogPath, repoRoot);
  await mkdir(dirname(target), { recursive: true });

  const logger: Logger = pino(
    {
      level: "info",
      base: undefined,
      timestamp: pino.stdTimeFunctions.isoTime,
      redact: {
        paths: REDACT_PATHS.flatMap((p) => [
          `args.${p}`,
          `args.headers.${p}`,
          `*.${p}`,
        ]),
        censor: "[REDACTED]",
      },
      formatters: {
        level: (label) => ({ level: label }),
      },
    },
    pinoDestination({
      dest: target,
      sync: true, // audit must not be lost on process exit
      mkdir: true,
      append: true,
    }),
  );

  return {
    path: target,
    record(event) {
      logger.info(event, "audit");
    },
    async flush() {
      // pino's sync destination writes immediately; provide a hook for symmetry.
      return Promise.resolve();
    },
  };
}

function resolveAuditPath(auditPath: string, repoRoot: string): string {
  if (isAbsolute(auditPath)) return auditPath;
  if (repoRoot === "auto") {
    // No repo resolved yet — write relative to CWD; the caller will have
    // already validated that CWD is sensible.
    return resolve(process.cwd(), auditPath);
  }
  return resolve(repoRoot, auditPath);
}

/** Convenience for unit tests: returns true if the audit file exists & is non-empty. */
export async function auditLogExists(path: string): Promise<boolean> {
  try {
    const s = await stat(path);
    return s.isFile() && s.size > 0;
  } catch {
    return false;
  }
}
