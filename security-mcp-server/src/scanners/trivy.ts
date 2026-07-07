import type { Logger } from "pino";
import { mkdir } from "node:fs/promises";
import { dirname, isAbsolute, join } from "node:path";
import { type RawScanResult, type ScanContext, type ScannerAdapter, buildFromTrivyVuln, checkAvailable, runBinary } from "./base.js";
import type { SecurityFinding } from "../findings.js";

export type TrivyMode = "fs" | "image" | "sbom";

export interface TrivyRunOptions {
  mode: TrivyMode;
  image?: string;
  sbomOutPath?: string;
}

export class TrivyAdapter implements ScannerAdapter {
  id = "trivy" as const;
  displayName = "Trivy (vuln / IaC / container / SBOM)";
  private readonly bin: string;
  private options: TrivyRunOptions = { mode: "fs" };
  private cachedVersion: string | undefined;

  constructor(binOverride?: string) {
    this.bin = binOverride ?? "trivy";
  }

  binaryPath(): string {
    return this.bin;
  }

  setOptions(opts: TrivyRunOptions): void {
    this.options = opts;
  }

  async isAvailable(): Promise<{ ok: boolean; version?: string; reason?: string }> {
    const res = await checkAvailable(this.bin, noopLogger());
    if (res.ok && res.version) this.cachedVersion = res.version;
    return res;
  }

  async run(ctx: ScanContext): Promise<RawScanResult> {
    const opts = this.options;
    if (opts.mode === "image") {
      const image = opts.image;
      if (!image) {
        return {
          scanner: "trivy",
          exitCode: 2,
          stdout: "",
          stderrExcerpt: "trivy image mode requires 'image' argument",
          durationMs: 0,
        };
      }
      const args = ["image", "--format", "json", "--output", "-", image];
      return runBinary(this.bin, args, { cwd: ctx.root, timeoutMs: ctx.config.scanTimeoutMs }, ctx.logger, "trivy");
    }
    if (opts.mode === "sbom") {
      const outPath = opts.sbomOutPath
        ? (isAbsolute(opts.sbomOutPath) ? opts.sbomOutPath : join(ctx.root, opts.sbomOutPath))
        : join(ctx.root, ".security-mcp", "sbom", "trivy.cdx.json");
      await mkdir(dirname(outPath), { recursive: true });
      const args = ["fs", "--format", "cyclonedx", "--output", outPath, "--", ctx.root];
      return runBinary(this.bin, args, { cwd: ctx.root, timeoutMs: ctx.config.scanTimeoutMs }, ctx.logger, "trivy");
    }
    // Default: fs (vuln + misconfig + secret + license)
    const args = ["fs", "--format", "json", "--output", "-", "--", ctx.root];
    return runBinary(this.bin, args, { cwd: ctx.root, timeoutMs: ctx.config.scanTimeoutMs }, ctx.logger, "trivy");
  }

  parse(raw: RawScanResult): SecurityFinding[] {
    if (this.options.mode === "sbom") return [];
    if (!raw.stdout) return [];
    let parsed: { Results?: unknown[] } = {};
    try {
      parsed = JSON.parse(raw.stdout);
    } catch {
      return [];
    }
    const results = Array.isArray(parsed.Results) ? (parsed.Results as Record<string, unknown>[]) : [];
    const out: SecurityFinding[] = [];
    for (const r of results) {
      const target = String(r.Target ?? "");
      const vulns = Array.isArray(r.Vulnerabilities) ? (r.Vulnerabilities as Record<string, unknown>[]) : [];
      for (const v of vulns) {
        out.push(buildFromTrivyVuln(v, target, this.cachedVersion));
      }
    }
    return out;
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
