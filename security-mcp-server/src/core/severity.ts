/**
 * Severity model. Two parallel scales:
 *   - `Severity` (5 levels) — what the model sees, what the reports group by.
 *   - `Level` (3 levels)    — SARIF-shaped "level" field (error | warning | note).
 *
 * Mappers exist for every scanner (Semgrep, Trivy, Gitleaks) and for CVSS.
 */

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

export const SEVERITY_ORDER: readonly Severity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

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

/** Map a Gitleaks severity (always high) — used by the gitleaks parser. */
export function severityFromGitleaks(): Severity {
  return "high";
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

/** Map a Severity to SARIF level. */
export function severityToLevel(sev: Severity): Level {
  if (sev === "critical" || sev === "high") return "error";
  if (sev === "medium") return "warning";
  return "note";
}

/** Severity color emoji (for Markdown reports). */
export function severityEmoji(sev: Severity): string {
  switch (sev) {
    case "critical":
      return "🛑";
    case "high":
      return "🔴";
    case "medium":
      return "🟠";
    case "low":
      return "🟡";
    case "info":
      return "🔵";
  }
}
