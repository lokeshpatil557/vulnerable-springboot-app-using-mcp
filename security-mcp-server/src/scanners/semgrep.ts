import type { Logger } from "pino";
import { type RawScanResult, type ScanContext, type ScannerAdapter, buildFromSemgrep, checkAvailable, runBinary } from "./base.js";
import type { SecurityFinding } from "../findings.js";
import { relativeToRepo } from "../paths.js";
import type { Config } from "../config.js";

export class SemgrepAdapter implements ScannerAdapter {
  id = "semgrep" as const;
  displayName = "Semgrep (SAST)";
  private readonly bin: string;
  private version: string | undefined;

  constructor(binOverride?: string) {
    this.bin = binOverride ?? "semgrep";
  }

  binaryPath(): string {
    return this.bin;
  }

  async isAvailable(): Promise<{ ok: boolean; version?: string; reason?: string }> {
    const res = await checkAvailable(this.bin, this.logger());
    if (res.ok && res.version) this.version = res.version;
    return res;
  }

  async run(ctx: ScanContext): Promise<RawScanResult> {
    const args: string[] = [
      "scan",
      "--json",
      "--quiet",
      "--error",
      "--no-git-ignore",
    ];
    for (const r of ctx.includeRuleSets ?? []) {
      args.push("--config", r);
    }
    if (ctx.extraRules && ctx.extraRules.length > 0) {
      for (const r of ctx.extraRules) args.push("--config", r);
    }
    args.push("--", ctx.target ?? ".");
    return runBinary(this.bin, args, { cwd: ctx.root, timeoutMs: ctx.config.scanTimeoutMs }, ctx.logger, "semgrep");
  }

  parse(raw: RawScanResult): SecurityFinding[] {
    if (!raw.stdout) return [];
    let parsed: { results?: unknown[] } = {};
    try {
      parsed = JSON.parse(raw.stdout);
    } catch {
      return [];
    }
    if (!Array.isArray(parsed.results)) return [];
    return (parsed.results as Record<string, unknown>[]).map((r) =>
      buildFromSemgrep(r, raw.version, relativeFromStart(r)),
    );
  }

  private logger(): Logger {
    // Lazy import to avoid a circular dep through config.
    // The actual logger is supplied at run-time via ctx; this is just for
    // version probing during isAvailable.
    return noopLogger();
  }
}

function relativeFromStart(r: Record<string, unknown>): string {
  const path = (r.path as string | undefined) ?? "";
  return path;
}

function noopLogger(): Logger {
  // Minimal pino-shaped logger; real logging uses ctx.logger during run().
  return {
    info: () => {},
    warn: () => {},
    error: () => {},
    debug: () => {},
    trace: () => {},
    fatal: () => {},
    child: () => noopLogger(),
    level: "info",
  } as unknown as Logger;
}

export { relativeToRepo };
