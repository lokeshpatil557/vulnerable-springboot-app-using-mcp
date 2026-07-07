import { execa, type ExecaError } from "execa";
import type { Logger } from "pino";
import type { Config } from "../config.js";
import { which } from "../util/shell.js";
import { withTimeout } from "../util/time.js";
import {
  type SecurityFinding,
  type ScannerId,
  type Severity,
  type Level,
  fingerprint as makeFingerprint,
  severityFromCvss,
  severityFromSemgrep,
  severityFromTrivy,
  maskSecret,
} from "../findings.js";
import { ScannerTimeoutError, ToolUnavailableError } from "../errors.js";

export interface ScanContext {
  /** Repo root. */
  root: string;
  /** Optional file/dir target inside the repo. */
  target?: string;
  /** Optional list of Semgrep rule packs to include. */
  includeRuleSets?: string[];
  /** Optional extra Semgrep YAML rule fragments. */
  extraRules?: string[];
  config: Config;
  logger: Logger;
}

export interface RawScanResult {
  /** Scanner id. */
  scanner: ScannerId;
  /** Scanner version (if discoverable). */
  version?: string;
  /** Exit code. */
  exitCode: number;
  /** Raw stdout (parsed into JSON by parsers). */
  stdout: string;
  /** Stderr excerpt (truncated). */
  stderrExcerpt?: string;
  /** Wall-clock duration in ms. */
  durationMs: number;
}

export interface ScannerAdapter {
  id: ScannerId;
  displayName: string;
  binaryPath(envOverride?: string): string;
  isAvailable(): Promise<{ ok: boolean; version?: string; reason?: string }>;
  run(ctx: ScanContext): Promise<RawScanResult>;
  parse(raw: RawScanResult): SecurityFinding[];
}

/**
 * Run a child process safely. Always uses array args (no shell). On Windows,
 * the `taskkill` cleanup path kills the process tree on timeout.
 */
export async function runBinary(
  bin: string,
  args: string[],
  options: {
    cwd: string;
    timeoutMs: number;
    input?: string | null;
    env?: NodeJS.ProcessEnv;
  },
  logger: Logger,
  label: string,
): Promise<RawScanResult> {
  const start = Date.now();
  try {
    const child = execa(bin, args, {
      cwd: options.cwd,
      timeout: options.timeoutMs,
      reject: false,
      input: options.input ?? null,
      env: options.env ?? process.env,
      maxBuffer: 256 * 1024 * 1024,
      stdio: ["pipe", "pipe", "pipe"],
      // shell: false is the default; left explicit for clarity.
      shell: false,
      windowsHide: true,
    });
    const res = await withTimeout(child, options.timeoutMs + 5_000, label);
    return {
      scanner: label as ScannerId,
      exitCode: res.exitCode ?? -1,
      stdout: typeof res.stdout === "string" ? res.stdout : "",
      stderrExcerpt: (res.stderr ?? "").toString().slice(0, 4_000),
      durationMs: Date.now() - start,
    };
  } catch (err) {
    const execaErr = err as ExecaError;
    if ((execaErr.timedOut ?? false) || /timeout after/i.test(String(err))) {
      throw new ScannerTimeoutError(label, options.timeoutMs);
    }
    logger.warn({ bin, args, err: String(err) }, "scanner run failed");
    return {
      scanner: label as ScannerId,
      exitCode: -1,
      stdout: "",
      stderrExcerpt: String(err).slice(0, 4_000),
      durationMs: Date.now() - start,
    };
  }
}

/** Helper: check that a binary is on PATH (or resolved via env override). */
export async function checkAvailable(
  bin: string,
  logger: Logger,
): Promise<{ ok: boolean; version?: string; reason?: string }> {
  const found = await which(bin);
  if (!found) {
    return { ok: false, reason: `binary '${bin}' not found on PATH` };
  }
  try {
    const res = await execa(found, ["--version"], { reject: false, timeout: 5_000 });
    const stdout = typeof res.stdout === "string" ? res.stdout : "";
    const stderr = typeof res.stderr === "string" ? res.stderr : "";
    const version = (stdout || stderr).split(/\r?\n/)[0]?.trim();
    return { ok: true, version };
  } catch (err) {
    logger.warn({ bin, err: String(err) }, "could not determine version");
    return { ok: true, reason: "version probe failed; binary exists" };
  }
}

// ---- Per-scanner finding builders ----------------------------------------

/** Build a `SecurityFinding` from a Semgrep result row. */
export function buildFromSemgrep(
  r: Record<string, unknown>,
  scannerVersion?: string,
  relPath = "",
): SecurityFinding {
  const start = (r.start as Record<string, number> | undefined) ?? { line: 0, col: 0 };
  const end = (r.end as Record<string, number> | undefined) ?? { line: 0, col: 0 };
  const extra = (r.extra as Record<string, unknown> | undefined) ?? {};
  const meta = (extra.metadata as Record<string, unknown> | undefined) ?? {};
  const cwe = normaliseStringArray(meta.cwe);
  const owasp = normaliseStringArray(meta.owasp);
  const message = String(extra.message ?? r.check_id ?? "");
  const ruleId = String(r.check_id ?? "unknown");
  const severity = severityFromSemgrep(String(extra.severity ?? ""));
  const level: Level = severity === "high" || severity === "critical" ? "error" : "warning";

  const fixRegex = (extra.fix_regex as Record<string, string> | undefined) ?? undefined;
  const fixDiff = (extra.fix as string | undefined) ?? undefined;
  const fixDescription = String(extra.fix_description ?? "");

  const finding: SecurityFinding = {
    id: makeFingerprint({ ruleId, path: relPath, startLine: start.line ?? 0, message }),
    ruleId,
    level,
    severity,
    message,
    location: {
      path: relPath,
      startLine: start.line ?? 0,
      endLine: end.line ?? start.line ?? 0,
      startColumn: start.col,
      endColumn: end.col,
    },
    cwe,
    owasp,
    category: "sast",
    tool: { name: "semgrep", version: scannerVersion },
    fingerprint: makeFingerprint({ ruleId, path: relPath, startLine: start.line ?? 0, message }),
    raw: r,
  };
  if (fixDiff) {
    finding.fix = { description: fixDescription || "Semgrep-provided fix", diff: fixDiff };
  } else if (fixRegex && fixRegex.regex && fixRegex.replacement) {
    finding.fix = {
      description: "Semgrep-provided regex fix",
      diff: `// apply regex: ${fixRegex.regex} -> ${fixRegex.replacement}`,
    };
  }
  return finding;
}

export function buildFromGitleaks(
  r: Record<string, unknown>,
  scannerVersion?: string,
  relPath = "",
): SecurityFinding {
  const ruleId = String(r.RuleID ?? "unknown");
  const startLine = Number(r.StartLine ?? r.Line ?? 0);
  const endLine = Number(r.EndLine ?? r.Line ?? startLine);
  const secret = String(r.Secret ?? "");
  const masked = maskSecret(secret);
  const message = `Possible secret leak (${ruleId}) — matched: ${masked}`;
  return {
    id: makeFingerprint({ ruleId, path: relPath, startLine, message }),
    ruleId,
    level: "error",
    severity: "high",
    message,
    location: {
      path: relPath,
      startLine,
      endLine,
    },
    cwe: ["CWE-798"],
    owasp: ["A07:2021 - Identification and Authentication Failures"],
    category: "secret",
    tool: { name: "gitleaks", version: scannerVersion },
    fingerprint: makeFingerprint({ ruleId, path: relPath, startLine, message }),
    raw: r,
  };
}

export function buildFromTrivyVuln(
  v: Record<string, unknown>,
  target: string,
  scannerVersion?: string,
): SecurityFinding {
  const cve = String(v.VulnerabilityID ?? "UNKNOWN");
  const pkg = String(v.PkgName ?? "");
  const installed = String(v.InstalledVersion ?? "");
  const fixed = String(v.FixedVersion ?? "");
  const title = String(v.Title ?? v.Description ?? "Vulnerability");
  const severity = severityFromTrivy(String(v.Severity ?? ""));
  const cvss = (v.CVSS as Record<string, unknown> | undefined) ?? null;
  const nvdScore = cvss?.nvd ? Number((cvss.nvd as Record<string, number>).V3Score ?? NaN) : NaN;
  const severityFromScore = severityFromCvss(Number.isFinite(nvdScore) ? nvdScore : null);
  const finalSeverity: Severity = severity === "info" ? severityFromScore : severity;
  const cweIds = normaliseStringArray(v.CweIDs);
  const message = `${cve} in ${pkg}@${installed}${fixed ? ` (fixed in ${fixed})` : ""}: ${title}`;
  return {
    id: makeFingerprint({ ruleId: cve, path: target, startLine: 0, message }),
    ruleId: cve,
    level: finalSeverity === "critical" || finalSeverity === "high" ? "error" : "warning",
    severity: finalSeverity,
    message,
    location: { path: target, startLine: 0, endLine: 0 },
    cwe: cweIds,
    cve: [cve].filter((x) => x !== "UNKNOWN"),
    owasp: [],
    category: "vuln",
    tool: { name: "trivy", version: scannerVersion },
    fingerprint: makeFingerprint({ ruleId: cve, path: target, startLine: 0, message }),
    raw: v,
  };
}

function normaliseStringArray(v: unknown): string[] {
  if (!v) return [];
  if (Array.isArray(v)) return v.filter((x) => typeof x === "string").map(String);
  if (typeof v === "string") return v.split(/[,\s]+/).filter(Boolean);
  return [];
}

export { ToolUnavailableError };
