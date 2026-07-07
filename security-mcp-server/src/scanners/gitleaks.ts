import type { Logger } from "pino";
import { type RawScanResult, type ScanContext, type ScannerAdapter, buildFromGitleaks, checkAvailable, runBinary } from "./base.js";
import type { SecurityFinding } from "../findings.js";
import { join } from "node:path";

export class GitleaksAdapter implements ScannerAdapter {
  id = "gitleaks" as const;
  displayName = "Gitleaks (secret detection)";
  private readonly bin: string;
  private version: string | undefined;

  constructor(binOverride?: string) {
    this.bin = binOverride ?? "gitleaks";
  }

  binaryPath(): string {
    return this.bin;
  }

  async isAvailable(): Promise<{ ok: boolean; version?: string; reason?: string }> {
    const res = await checkAvailable(this.bin, noopLogger());
    if (res.ok && res.version) this.version = res.version;
    return res;
  }

  async run(ctx: ScanContext): Promise<RawScanResult> {
    const target = ctx.target ?? ctx.root;
    const args: string[] = [
      "detect",
      "--no-banner",
      "--no-git",
      "--source", ctx.root,
      "--report-format", "json",
      "--report-path", "-",
      "--exit-code", "0",
    ];
    // For a single-file scan we pass the file path at the end.
    if (ctx.target && ctx.target !== ctx.root) {
      args.push(join(ctx.root, ctx.target));
    }
    return runBinary(this.bin, args, { cwd: ctx.root, timeoutMs: ctx.config.scanTimeoutMs }, ctx.logger, "gitleaks");
  }

  parse(raw: RawScanResult): SecurityFinding[] {
    if (!raw.stdout) return [];
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw.stdout);
    } catch {
      return [];
    }
    if (!Array.isArray(parsed)) return [];
    return (parsed as Record<string, unknown>[]).map((r) => buildFromGitleaks(r, raw.version, String(r.File ?? "")));
  }
}

function noopLogger(): Logger {
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
