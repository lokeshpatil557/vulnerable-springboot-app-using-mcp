/**
 * GitleaksScanner — runs `gitleaks detect` against a repository path (or
 * a single file inside it) and normalizes the JSON report to
 * `SecurityFinding[]`.
 *
 * Design notes:
 *   - **Output**: `--report-format json --report-path -` writes the JSON
 *     report to stdout, which `parse()` then reads.
 *   - **Exit code**: `--exit-code 0` is passed so Gitleaks does not exit
 *     non-zero when findings are present (Gitleaks' default is 1). The
 *     `parse()` function reads from `stdout` regardless of `exitCode`, so
 *     partial findings are preserved.
 *   - **Git integration**: `--no-git` is passed so the scan works on
 *     plain directories, not just git work trees. This is what the
 *     `run_secret_scan` and `scan_file` tools want — they target
 *     arbitrary paths inside the allowed repo root.
 *   - **No secret leaks**: `buildFromGitleaks()` in `base.ts` strips
 *     the `Secret` and `Match` fields from the raw payload before it is
 *     attached to the finding, and the message uses the masked
 *     fingerprint (last-4 chars only). The raw secret value never
 *     reaches the MCP response.
 *   - **Severity**: always `critical` or `high` per spec — see
 *     `severityFromGitleaksRule()` in `base.ts` for the rule-id mapping.
 *   - **Timeout**: enforced by `runBinary` via `withTimeout`. Hard
 *     timeout is `ctx.config.scanTimeoutMs`.
 *   - **Target flexibility**: a single file path can be passed via
 *     `ctx.target`; otherwise the whole repo (`ctx.root`) is scanned.
 */
import type { Logger } from "pino";
import { join } from "node:path";
import {
  type RawScanResult,
  type ScanContext,
  type ScannerAdapter,
  buildFromGitleaks,
  checkAvailable,
  runBinary,
} from "./base.js";
import type { SecurityFinding } from "../core/finding.js";

/** Hard cap on the number of findings we'll surface from a single scan. */
const MAX_FINDINGS = 10_000;

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

  /**
   * Re-point this adapter at a different binary. Used by the
   * `ToolManager` after it has resolved a scanner on PATH. See the
   * matching method on `SemgrepAdapter` for the cast rationale.
   */
  setBinaryPath(path: string): void {
    (this as unknown as { bin: string }).bin = path;
  }

  async isAvailable(): Promise<{ ok: boolean; version?: string; reason?: string }> {
    const res = await checkAvailable(this.bin, this.logger());
    if (res.ok && res.version) this.version = res.version;
    return res;
  }

  /**
   * Run `gitleaks detect` against `ctx.root`, or against the single file
   * at `ctx.target` if one was supplied. JSON report goes to stdout.
   */
  async run(ctx: ScanContext): Promise<RawScanResult> {
    const args: string[] = [
      "detect",
      "--no-banner",
      "--no-git",
      "--source", ctx.root,
      "--report-format", "json",
      "--report-path", "-",
      "--exit-code", "0",
    ];
    // For a single-file scan, append the absolute file path as a positional
    // argument. Gitleaks accepts a path argument that scopes the scan.
    if (ctx.target && ctx.target !== ctx.root) {
      args.push(join(ctx.root, ctx.target));
    }
    return runBinary(
      this.bin,
      args,
      { cwd: ctx.root, timeoutMs: ctx.config.scanTimeoutMs },
      ctx.logger,
      "gitleaks",
    );
  }

  /**
   * Parse the Gitleaks JSON report. The top-level shape is a JSON array
   * of finding rows. `Secret` / `Match` are stripped by
   * `buildFromGitleaks` so the response cannot leak the raw value.
   *
   * Tolerant of:
   *   - empty stdout (clean scan) → `[]`
   *   - unparseable stdout → `[]` (no throw)
   *   - non-zero exit (findings present) → still parses stdout
   */
  parse(raw: RawScanResult): SecurityFinding[] {
    if (!raw.stdout) return [];
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw.stdout);
    } catch {
      return [];
    }
    if (!Array.isArray(parsed)) return [];
    const rows = (parsed as Record<string, unknown>[]).slice(0, MAX_FINDINGS);
    return rows.map((r) => buildFromGitleaks(r, raw.version ?? this.version, String(r.File ?? "")));
  }

  private logger(): Logger {
    // Real logging flows through ctx.logger during run(); this stub is
    // only used for the version probe in `isAvailable`.
    return noopLogger();
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
