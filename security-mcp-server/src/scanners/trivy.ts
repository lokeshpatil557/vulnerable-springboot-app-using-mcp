/**
 * TrivyScanner — runs Trivy against a repo, a container image, or
 * produces a CycloneDX SBOM. Supports all five Trivy `fs` scanners
 * (vuln, misconfig, secret, license, plus the default `vuln`).
 *
 * Modes (`setOptions({ mode })`):
 *   - `"fs"`    — Trivy filesystem scan. Default. Includes
 *                 vulnerabilities, misconfigurations, secrets, and
 *                 licenses (one Trivy invocation covers all four).
 *   - `"image"` — Trivy image scan for a single container image.
 *   - `"sbom"`  — Trivy SBOM generation. CycloneDX JSON written to
 *                 `.security-mcp/sbom/trivy.cdx.json` (or
 *                 `sbomOutPath` if provided). `parse()` returns `[]`
 *                 in this mode; consumers should read the file.
 *
 * Design notes:
 *   - **Output**: `--format json --output -` writes findings to stdout.
 *   - **SBOM**: `--format cyclonedx --output <path>` writes the SBOM
 *     to a file (not stdout, because CycloneDX is large).
 *   - **Exit code**: Trivy exits non-zero when findings are present.
 *     `parse()` reads from `stdout` regardless, so partial findings
 *     are preserved.
 *   - **Timeout**: enforced by `runBinary` via `withTimeout`, which
 *     kills the process tree on Windows and throws
 *     `ScannerTimeoutError` on overrun.
 *   - **Sandbox**: scan target is `ctx.root` for `fs` / `sbom`;
 *     `image` mode reads from the local Docker daemon / registry and
 *     runs with `cwd = ctx.root` (Trivy writes nothing to cwd).
 *   - **Category mapping** (per spec):
 *       - `Results[].Vulnerabilities[]`  → `category: "dependency"`
 *       - `Results[].Misconfigurations[]` → `category: "container"`
 *         for k8s/Dockerfile/Helm; `category: "config"` for other IaC.
 *       - `Results[].Secrets[]`         → `category: "secret"`
 *       - `Results[].Licenses[]`        → `category: "config"`
 *     See `buildFromTrivyVuln` / `buildFromTrivyMisconfig` /
 *     `buildFromTrivySecret` / `buildFromTrivyLicense` in `base.ts`.
 */
import type { Logger } from "pino";
import { mkdir } from "node:fs/promises";
import { dirname, isAbsolute, join } from "node:path";
import {
  type RawScanResult,
  type ScanContext,
  type ScannerAdapter,
  buildFromTrivyLicense,
  buildFromTrivyMisconfig,
  buildFromTrivySecret,
  buildFromTrivyVuln,
  checkAvailable,
  runBinary,
} from "./base.js";
import type { SecurityFinding } from "../core/finding.js";

export type TrivyMode = "fs" | "image" | "sbom";

export interface TrivyRunOptions {
  mode: TrivyMode;
  image?: string;
  sbomOutPath?: string;
}

/**
 * Hard caps. Trivy can surface a *lot* of license findings on large
 * repos; the cap keeps memory bounded. Excess rows are dropped silently
 * (Trivy's own severity ordering is preserved within the cap).
 */
const MAX_FINDINGS_PER_TYPE = 25_000;
const MAX_FINDINGS_TOTAL = 50_000;

export class TrivyAdapter implements ScannerAdapter {
  id = "trivy" as const;
  displayName = "Trivy (vuln / IaC / container / SBOM)";
  private readonly bin: string;
  private options: TrivyRunOptions = { mode: "fs" };
  private version: string | undefined;

  constructor(binOverride?: string) {
    this.bin = binOverride ?? "trivy";
  }

  binaryPath(): string {
    return this.bin;
  }

  /** Update the mode / image / sbom output path between calls. */
  setOptions(opts: TrivyRunOptions): void {
    this.options = opts;
  }

  async isAvailable(): Promise<{ ok: boolean; version?: string; reason?: string }> {
    const res = await checkAvailable(this.bin, this.logger());
    if (res.ok && res.version) this.version = res.version;
    return res;
  }

  /**
   * Build the argv for the current `options.mode` and invoke Trivy.
   * `fs` runs all four scanners (vuln, misconfig, secret, license) in
   * a single Trivy invocation; the parse() pass then dispatches each
   * result type to the right `buildFrom*` normaliser.
   */
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
      const args = [
        "image",
        "--format", "json",
        "--output", "-",
        "--scanners", "vuln,secret",
        image,
      ];
      return runBinary(
        this.bin,
        args,
        { cwd: ctx.root, timeoutMs: ctx.config.scanTimeoutMs },
        ctx.logger,
        "trivy",
      );
    }

    if (opts.mode === "sbom") {
      const outPath = opts.sbomOutPath
        ? (isAbsolute(opts.sbomOutPath) ? opts.sbomOutPath : join(ctx.root, opts.sbomOutPath))
        : join(ctx.root, ".security-mcp", "sbom", "trivy.cdx.json");
      await mkdir(dirname(outPath), { recursive: true });
      const args = [
        "fs",
        "--format", "cyclonedx",
        "--output", outPath,
        "--", ctx.root,
      ];
      return runBinary(
        this.bin,
        args,
        { cwd: ctx.root, timeoutMs: ctx.config.scanTimeoutMs },
        ctx.logger,
        "trivy",
      );
    }

    // Default: `fs` with all four scanners enabled.
    const args = [
      "fs",
      "--format", "json",
      "--output", "-",
      "--scanners", "vuln,misconfig,secret,license",
      "--", ctx.root,
    ];
    return runBinary(
      this.bin,
      args,
      { cwd: ctx.root, timeoutMs: ctx.config.scanTimeoutMs },
      ctx.logger,
      "trivy",
    );
  }

  /**
   * Walk every `Results[]` row in the Trivy JSON document and dispatch
   * each finding type to its normaliser:
   *
   *   - `Vulnerabilities[]`  → `buildFromTrivyVuln`     (category: dependency)
   *   - `Misconfigurations[]`→ `buildFromTrivyMisconfig` (category: container | config)
   *   - `Secrets[]`          → `buildFromTrivySecret`   (category: secret)
   *   - `Licenses[]`         → `buildFromTrivyLicense`  (category: config)
   *
   * Trivy emits one `Results[]` row per scan target (a single manifest,
   * a single lockfile, etc.), so each row carries its own `Target` and
   * `Class` (e.g. `"os-pkgs"`, `"lang-pkgs"`, `"config"`).
   *
   * SBOM mode returns `[]` — the SBOM is a file, not findings.
   */
  parse(raw: RawScanResult): SecurityFinding[] {
    if (this.options.mode === "sbom") return [];
    if (!raw.stdout) return [];
    let parsed: { Results?: unknown[] } = {};
    try {
      parsed = JSON.parse(raw.stdout);
    } catch {
      return [];
    }
    const results = Array.isArray(parsed.Results)
      ? (parsed.Results as Record<string, unknown>[])
      : [];
    const out: SecurityFinding[] = [];
    const version = raw.version ?? this.version;
    for (const r of results) {
      const target = String(r.Target ?? "");
      const cls = String(r.Class ?? "");
      const isContainer = /os-pkgs/.test(cls) === false && /dockerfile|kubernetes|k8s|helm|iac/i.test(`${target} ${cls}`);

      // 1. Vulnerabilities → dependency category
      const vulns = Array.isArray(r.Vulnerabilities)
        ? (r.Vulnerabilities as Record<string, unknown>[]).slice(0, MAX_FINDINGS_PER_TYPE)
        : [];
      for (const v of vulns) {
        if (out.length >= MAX_FINDINGS_TOTAL) return out;
        out.push(buildFromTrivyVuln(v, target, version));
      }

      // 2. Misconfigurations → container / config
      const misconfs = Array.isArray(r.Misconfigurations)
        ? (r.Misconfigurations as Record<string, unknown>[]).slice(0, MAX_FINDINGS_PER_TYPE)
        : [];
      for (const m of misconfs) {
        if (out.length >= MAX_FINDINGS_TOTAL) return out;
        const f = buildFromTrivyMisconfig(m, target, version);
        // For filesystem scans, `isContainer` is determined by the
        // builder already; for image scans, force the category to
        // "container" since the target is by definition a container.
        if (this.options.mode === "image" && f.category === "config") f.category = "container";
        if (isContainer && f.category === "config") f.category = "container";
        out.push(f);
      }

      // 3. Secrets → secret
      const secrets = Array.isArray(r.Secrets)
        ? (r.Secrets as Record<string, unknown>[]).slice(0, MAX_FINDINGS_PER_TYPE)
        : [];
      for (const s of secrets) {
        if (out.length >= MAX_FINDINGS_TOTAL) return out;
        out.push(buildFromTrivySecret(s, target, version));
      }

      // 4. Licenses → config
      const licenses = Array.isArray(r.Licenses)
        ? (r.Licenses as Record<string, unknown>[]).slice(0, MAX_FINDINGS_PER_TYPE)
        : [];
      for (const l of licenses) {
        if (out.length >= MAX_FINDINGS_TOTAL) return out;
        out.push(buildFromTrivyLicense(l, target, version));
      }
    }
    return out;
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
