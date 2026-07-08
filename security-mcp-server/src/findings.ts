/**
 * Canonical normalized security finding. Aligned with SARIF 2.1.0 result
 * shape (id/ruleId/level/message/location/cwe/cve/owasp/properties) but
 * intentionally a subset — not a spec-compliant SARIF document.
 */

import { shortHash } from "./util/hash.js";

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Level = "error" | "warning" | "note";
export type Category =
  | "sast"
  | "secret"
  | "vuln"
  | "config"
  | "iac"
  | "dependency"
  | "container";

export type ScannerId = "semgrep" | "gitleaks" | "trivy";

export interface FindingLocation {
  /** Repo-relative path. */
  path: string;
  startLine: number;
  endLine: number;
  startColumn?: number;
  endColumn?: number;
}

export interface FindingFix {
  description: string;
  /** Unified diff (single file) — empty string means "manual review required". */
  diff: string;
  /** Confidence in the auto-generated fix. */
  confidence?: "high" | "low";
}

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
  /** Stable sha256-prefix used for dedup & verification. */
  fingerprint: string;
  /** Original tool payload, omitted from reports. */
  raw?: unknown;
}

/** Build a stable 16-char fingerprint from the rule + location + message. */
export function fingerprint(parts: {
  ruleId: string;
  path: string;
  startLine: number;
  message: string;
}): string {
  const key = [parts.ruleId, parts.path, parts.startLine, parts.message].join("|");
  return shortHash(key, 16);
}

/** Map a CVSS base score (0-10) to a normalized severity. */
export function severityFromCvss(score: number | null | undefined): Severity {
  if (score == null || !Number.isFinite(score)) return "medium";
  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "medium";
  if (score > 0.0) return "low";
  return "info";
}

/** Map a Semgrep severity string to our Severity. */
export function severityFromSemgrep(s: string | undefined): Severity {
  switch ((s ?? "").toLowerCase()) {
    case "error":
      return "high";
    case "warning":
      return "medium";
    case "info":
      return "low";
    default:
      return "medium";
  }
}

/** Map a Trivy severity string to our Severity. */
export function severityFromTrivy(s: string | undefined): Severity {
  switch ((s ?? "").toUpperCase()) {
    case "CRITICAL":
      return "critical";
    case "HIGH":
      return "high";
    case "MEDIUM":
      return "medium";
    case "LOW":
      return "low";
    case "UNKNOWN":
    case "":
      return "info";
    default:
      return "medium";
  }
}

/** Map a SARIF level to our Level. */
export function levelFromSarif(s: string | undefined): Level {
  switch ((s ?? "").toLowerCase()) {
    case "error":
      return "error";
    case "warning":
      return "warning";
    case "note":
      return "note";
    case "none":
    default:
      return "note";
  }
}

/** Map a Severity to SARIF level (SARIF only has 4 levels). */
export function severityToLevel(sev: Severity): Level {
  if (sev === "critical" || sev === "high") return "error";
  if (sev === "medium") return "warning";
  return "note";
}

/** Mask a secret value to its last 4 characters — never return it whole. */
export function maskSecret(secret: string | undefined | null): string {
  if (!secret) return "";
  if (secret.length <= 4) return "*".repeat(secret.length);
  return "*".repeat(Math.max(0, secret.length - 4)) + secret.slice(-4);
}
