import { mkdir } from "node:fs/promises";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { createWriteStream, type WriteStream } from "node:fs";
import { randomUUID } from "node:crypto";

export type AuditOutcome = "ok" | "error" | "unavailable" | "denied";

export interface AuditEvent {
  ts: string;
  tool: string;
  args: unknown;
  findingCount: number;
  durationMs: number;
  outcome: AuditOutcome;
  errorCode: string | null;
  /** Optional per-request correlation id. */
  requestId?: string;
  /** Per-tool actor (e.g. the model session, user id). */
  actor?: string;
  /** Path-safety flag — did any arg try to escape the repo? */
  pathSafe?: boolean;
}

export interface AuditLoggerOptions {
  /** Absolute or repo-relative path to the JSONL audit file. */
  path: string;
  /** Repo root for resolving relative paths. */
  repoRoot: string;
  /** When true, use a sync file descriptor (no buffering). Default: true. */
  sync?: boolean;
  /** Hard cap on the in-memory ring buffer (for tests / dashboards). Default: 100. */
  bufferSize?: number;
}

/**
 * Append-only JSONL audit logger. Each `record` call writes one line and (when
 * a buffer is enabled) also keeps the most recent events in memory for tests.
 */
export class AuditLogger {
  private stream: WriteStream | undefined;
  private buffer: AuditEvent[] = [];
  private readonly bufferSize: number;
  readonly path: string;
  private closed = false;

  constructor(opts: AuditLoggerOptions) {
    this.path = resolvePath(opts.path, opts.repoRoot);
    this.bufferSize = opts.bufferSize ?? 100;
    // Lazy: do not mkdir synchronously in the constructor.
  }

  /** Initialise the underlying stream. Call before the first `record`. */
  async init(): Promise<void> {
    await mkdir(dirname(this.path), { recursive: true });
    this.stream = createWriteStream(this.path, { flags: "a", encoding: "utf8" });
  }

  record(event: AuditEvent): void {
    if (this.closed) return;
    // Augment with default fields.
    const enriched: AuditEvent = {
      requestId: event.requestId ?? randomUUID(),
      ...event,
    };
    // Push to ring buffer.
    this.buffer.push(enriched);
    if (this.buffer.length > this.bufferSize) this.buffer.shift();
    // Write JSONL line.
    try {
      this.stream?.write(JSON.stringify(enriched) + "\n");
    } catch {
      // best-effort; never crash the calling tool
    }
  }

  /** Snapshot the in-memory ring buffer. */
  recent(): readonly AuditEvent[] {
    return [...this.buffer];
  }

  /** Flush + close the underlying stream. Idempotent. */
  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    const stream = this.stream;
    if (stream) {
      await new Promise<void>((resolve) => {
        stream.end(() => resolve());
      });
    }
  }
}

function resolvePath(auditPath: string, repoRoot: string): string {
  if (isAbsolute(auditPath)) return auditPath;
  return resolve(repoRoot, auditPath);
}

/** Convenience factory: build, init, return. */
export async function createAuditLogger(
  options: AuditLoggerOptions,
): Promise<AuditLogger> {
  const logger = new AuditLogger(options);
  await logger.init();
  return logger;
}
