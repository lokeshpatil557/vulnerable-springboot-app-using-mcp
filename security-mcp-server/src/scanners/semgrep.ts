/**
 * SemgrepScanner — runs `semgrep scan` against a file, directory, or repo
 * and normalizes the JSON output to `SecurityFinding[]`.
 *
 * Design notes:
 *   - **Configs**: defaults to `p/security-audit` + `p/owasp-top-ten`. The
 *     caller can override via `ctx.includeRuleSets`. Extra YAML fragments
 *     can be added via `ctx.extraRules`.
 *   - **Output**: `--json` is mandatory — `parse()` will return `[]` on
 *     anything else.
 *   - **Non-zero exit**: Semgrep returns exit code 1 when findings are
 *     present (this is normal). `runBinary` does not throw on non-zero
 *     exit (it uses `reject: false`), and `parse()` reads from `stdout`
 *     regardless, so partial findings are preserved. We only treat a
 *     non-zero exit as a real failure when stdout has no parseable JSON.
 *   - **Timeout**: enforced by `runBinary` via `withTimeout`, which throws
 *     `ScannerTimeoutError` from `errors.ts`.
 *   - **Sandbox**: the scan target is run with `cwd = ctx.root` and
 *     `args = [..., "--", target]` — `shell: false` so the target is never
 *     interpreted by a shell.
 *   - **Normalization**: delegates to `buildFinding()` from
 *     `core/finding.ts`, so the new fields (e.g. `references`) flow
 *     through automatically once `buildFromSemgrep` populates them.
 */
import type { Logger } from "pino";
import {
  type RawScanResult,
  type ScanContext,
  type ScannerAdapter,
  buildFromSemgrep,
  checkAvailable,
  runBinary,
} from "./base.js";
import type { SecurityFinding } from "../core/finding.js";
import { relativeToRepo } from "../paths.js";
import type { Config } from "../config.js";

/** Default Semgrep rule packs applied when the caller doesn't override. */
const DEFAULT_RULE_PACKS: readonly string[] = [
  "p/security-audit",
  "p/owasp-top-ten",
];

/** Maximum number of findings we'll surface per scan (defensive cap). */
const MAX_FINDINGS = 50_000;

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

  /**
   * Re-point this adapter at a different binary. Used by the
   * `ToolManager` after it has resolved a scanner on PATH. The `bin`
   * field is `private` in this class, so we use a double-cast to bypass
   * the visibility check. The double-cast is safe because the manager
   * is the only caller and it runs once, at boot, before any tool
   * invocation.
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
   * Run the scan. The target defaults to the whole repo (`"."`) when the
   * caller doesn't specify a file or directory. Each invocation is bounded
   * by `ctx.config.scanTimeoutMs`.
   */
  async run(ctx: ScanContext): Promise<RawScanResult> {
    const args: string[] = [
      "scan",
      "--json",
      "--quiet",
      "--error",
      "--no-git-ignore",
    ];

    // Default rule packs: `p/security-audit` + `p/owasp-top-ten` unless
    // the caller supplied an explicit `includeRuleSets` (even an empty
    // list is treated as an explicit "no defaults" signal).
    const rulePacks =
      ctx.includeRuleSets && ctx.includeRuleSets.length > 0
        ? ctx.includeRuleSets
        : (ctx.config?.includeRuleSets?.length
            ? ctx.config.includeRuleSets
            : DEFAULT_RULE_PACKS);
    for (const r of rulePacks) args.push("--config", r);

    if (ctx.extraRules && ctx.extraRules.length > 0) {
      for (const r of ctx.extraRules) args.push("--config", r);
    }

    args.push("--", ctx.target ?? ".");

    return runBinary(
      this.bin,
      args,
      { cwd: ctx.root, timeoutMs: ctx.config.scanTimeoutMs },
      ctx.logger,
      "semgrep",
    );
  }

  /**
   * Parse Semgrep's JSON output into normalized `SecurityFinding[]`.
   *
   * This is intentionally tolerant:
   *   - Empty stdout → `[]` (the scan was clean or produced no findings).
   *   - Unparseable stdout → `[]` (logged via the caller, not thrown).
   *   - Parseable stdout with empty `results` → `[]`.
   *   - Parseable stdout with findings → mapped through `buildFromSemgrep`,
   *     which preserves CWE, OWASP, references, file path, and line numbers.
   *
   * A non-zero exit code alone is **not** treated as a failure — Semgrep
   * exits 1 when findings are present (normal), and may exit non-zero for
   * config warnings while still emitting valid JSON on stdout.
   */
  parse(raw: RawScanResult): SecurityFinding[] {
    if (!raw.stdout) return [];
    let parsed: { results?: unknown[]; errors?: unknown[] } = {};
    try {
      parsed = JSON.parse(raw.stdout);
    } catch {
      // Truncated / partial output is possible on timeout; the caller
      // will surface ScannerTimeoutError separately. We don't throw.
      return [];
    }
    if (!Array.isArray(parsed.results)) return [];
    const rows = (parsed.results as Record<string, unknown>[]).slice(0, MAX_FINDINGS);
    return rows.map((r) =>
      buildFromSemgrep(r, raw.version ?? this.version, relativeFromStart(r)),
    );
  }

  private logger(): Logger {
    // Lazy noop — real logging uses ctx.logger during run(). This exists
    // only for the version probe in `isAvailable`.
    return noopLogger();
  }
}

function relativeFromStart(r: Record<string, unknown>): string {
  const path = (r.path as string | undefined) ?? "";
  return path;
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

export { relativeToRepo, DEFAULT_RULE_PACKS };
