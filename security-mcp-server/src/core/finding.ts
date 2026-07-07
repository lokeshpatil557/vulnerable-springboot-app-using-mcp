import { sha256Hex } from "../utils/file-utils.js";
import {
  type Severity,
  type Level,
  type Category,
  severityToLevel,
  type severityFromCvss as _SeverityFromCvss,
} from "./severity.js";
import { maskSecret } from "../security/redaction.js";

/** Re-export Severity / Level / Category for convenience. */
export type { Severity, Level, Category };

/** Where the finding was detected. */
export interface FindingLocation {
  path: string;
  startLine: number;
  endLine: number;
  startColumn?: number;
  endColumn?: number;
}

/** Proposed fix (unified diff, may be empty for manual review). */
export interface FindingFix {
  description: string;
  diff: string;
}

/** Tool identifier — one of the three scanners. */
export type ScannerId = "semgrep" | "gitleaks" | "trivy";

/** Normalized, SARIF-shaped security finding. */
export interface SecurityFinding {
  id: string;
  ruleId: string;
  level: Level;
  severity: Severity;
  message: string;
  location: FindingLocation;
  cwe: string[];
  cve?: string[];
  owasp?: string[];
  /** External reference URLs (e.g. from Semgrep's `metadata.references`). */
  references?: string[];
  category: Category;
  tool: { name: ScannerId; version?: string };
  fix?: FindingFix;
  /** Stable 16-char fingerprint used for dedup & verification. */
  fingerprint: string;
  /** Original tool payload — omitted from reports. */
  raw?: unknown;
}

/** Compute a stable fingerprint from rule + location + message. */
export function fingerprint(parts: {
  ruleId: string;
  path: string;
  startLine: number;
  message: string;
}): string {
  const key = [parts.ruleId, parts.path, parts.startLine, parts.message].join("|");
  return sha256Hex(key).slice(0, 16);
}

/** Builder helper used by per-scanner normalizers. */
export interface FindingBuilder {
  id?: string;
  ruleId: string;
  severity: Severity;
  message: string;
  location: FindingLocation;
  cwe?: string[];
  cve?: string[];
  owasp?: string[];
  references?: string[];
  category: Category;
  tool: { name: ScannerId; version?: string };
  fix?: FindingFix;
  raw?: unknown;
}

export function buildFinding(b: FindingBuilder): SecurityFinding {
  const id = b.id ?? fingerprint({
    ruleId: b.ruleId,
    path: b.location.path,
    startLine: b.location.startLine,
    message: b.message,
  });
  // Apply secret masking to messages from secret scanners.
  const message = b.category === "secret" ? maskMessage(b.message) : b.message;
  const f: SecurityFinding = {
    id,
    ruleId: b.ruleId,
    level: severityToLevel(b.severity),
    severity: b.severity,
    message,
    location: b.location,
    cwe: b.cwe ?? [],
    category: b.category,
    tool: b.tool,
    fingerprint: id,
  };
  if (b.cve && b.cve.length > 0) f.cve = b.cve;
  if (b.owasp && b.owasp.length > 0) f.owasp = b.owasp;
  if (b.references && b.references.length > 0) f.references = b.references;
  if (b.fix) f.fix = b.fix;
  if (b.raw !== undefined) f.raw = b.raw;
  return f;
}

/** For secret-category findings, ensure the message never embeds the raw secret. */
function maskMessage(msg: string): string {
  // Heuristic: if a long uppercase / hex run is present, mask it.
  return msg.replace(/[A-Za-z0-9_\-+/=]{16,}/g, (m) => maskSecret(m));
}

// --- Remediation result ---------------------------------------------------

/** Outcome of a single `verify_fix` check for one finding. */
export type VerifyOutcome = "fixed" | "still_present" | "not_found_in_storage";

/** One entry in a `verify_fix` batch response. */
export interface VerifyFixEntry {
  findingId: string;
  outcome: VerifyOutcome;
  /** Fingerprint of the matching finding, if still present. */
  fingerprint?: string;
  /** If `still_present`, the regenerated finding (post-apply). */
  finding?: SecurityFinding;
}

/**
 * Result returned by `RemediationEngine.propose()` and the
 * `generate_remediation` MCP tool. Read-only — does not modify files.
 */
export interface GenerateRemediationResult {
  findingId: string;
  fingerprint: string;
  description: string;
  /** Unified diff (single file). Empty string means "manual review required". */
  diff: string;
  /** Confidence in the auto-generated fix. */
  confidence: "high" | "low";
  /** Where the fix was sourced from. */
  source: "semgrep_provided" | "rule_template" | "manual_review" | "no_fix";
}

/**
 * Result returned by `RemediationEngine.apply()` and the
 * `apply_remediation` MCP tool. `acknowledged: true` is required.
 */
export interface ApplyRemediationResult {
  findingId: string;
  applied: boolean;
  /** Absolute path of the timestamped backup file. */
  backupPath: string;
  /** Unified diff that was applied (single file). */
  diff: string;
  /** True if the change was rolled back because the scanner still flagged it. */
  rolledBack?: boolean;
  /** Reason for rollback, if any. */
  rollbackReason?: string;
}

/**
 * Result returned by the `verify_fix` MCP tool: one entry per requested
 * finding id.
 */
export interface VerifyFixResult {
  scanId: string;
  results: VerifyFixEntry[];
  /** Aggregate counts for quick UI display. */
  summary: {
    fixed: number;
    stillPresent: number;
    notFound: number;
  };
}

/** Discriminated union of all three remediation outcomes. */
export type RemediationResult =
  | ({ kind: "generate" } & GenerateRemediationResult)
  | ({ kind: "apply" } & ApplyRemediationResult)
  | ({ kind: "verify" } & VerifyFixResult);

// --- Normalization --------------------------------------------------------

import {
  buildFromSemgrep,
  buildFromGitleaks,
  buildFromTrivyVuln,
} from "../scanners/base.js";

/** Options for `normalizeFinding`. */
export interface NormalizeOptions {
  /** Scanner-reported version string. Forwarded into `tool.version`. */
  scannerVersion?: string;
  /**
   * For Trivy: the file or directory the scan targeted (e.g. "pom.xml" or
   * "."). Used as the finding's `location.path` for package-level CVEs.
   */
  target?: string;
}

/**
 * Normalize a raw row from any supported scanner into a `SecurityFinding`.
 *
 * Dispatch is keyed on `scanner`:
 *   - `semgrep`  → uses Semgrep's JSON output (top-level `results[]` rows).
 *   - `gitleaks` → uses Gitleaks' JSON array elements.
 *   - `trivy`    → uses Trivy's `Results[].Vulnerabilities[]` rows.
 *
 * Unknown scanners throw — fail loud rather than silently producing
 * poorly-normalized findings.
 */
export function normalizeFinding(
  scanner: ScannerId,
  raw: unknown,
  options: NormalizeOptions = {},
): SecurityFinding {
  if (raw === null || typeof raw !== "object") {
    throw new TypeError(
      `normalizeFinding: expected an object, got ${raw === null ? "null" : typeof raw}`,
    );
  }
  const r = raw as Record<string, unknown>;
  switch (scanner) {
    case "semgrep":
      return buildFromSemgrep(r, options.scannerVersion, options.target ?? "");
    case "gitleaks":
      return buildFromGitleaks(r, options.scannerVersion, options.target ?? "");
    case "trivy":
      return buildFromTrivyVuln(r, options.target ?? "", options.scannerVersion);
    default: {
      const _exhaustive: never = scanner;
      throw new TypeError(
        `normalizeFinding: unknown scanner '${String(_exhaustive)}' — expected 'semgrep' | 'gitleaks' | 'trivy'`,
      );
    }
  }
}

/**
 * Normalize a batch of raw rows. Rows that fail to normalize (e.g. malformed
 * JSON) are reported in `errors` and skipped — the rest of the batch still
 * surfaces as `SecurityFinding`s.
 */
export function normalizeFindings(
  scanner: ScannerId,
  rows: readonly unknown[],
  options: NormalizeOptions = {},
): { findings: SecurityFinding[]; errors: { index: number; error: string }[] } {
  const findings: SecurityFinding[] = [];
  const errors: { index: number; error: string }[] = [];
  rows.forEach((row, index) => {
    try {
      findings.push(normalizeFinding(scanner, row, options));
    } catch (err) {
      errors.push({ index, error: (err as Error).message });
    }
  });
  return { findings, errors };
}
