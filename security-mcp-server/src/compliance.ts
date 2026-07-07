import type { SecurityFinding } from "./findings.js";

/** Count findings grouped by OWASP Top 10 category (e.g. "A01:2021"). */
export function groupByOwasp(findings: SecurityFinding[]): Record<string, number> {
  const out: Record<string, number> = {};
  for (const f of findings) {
    for (const tag of f.owasp ?? []) {
      out[tag] = (out[tag] ?? 0) + 1;
    }
  }
  return Object.fromEntries(Object.entries(out).sort((a, b) => b[1] - a[1]));
}

/** Count findings grouped by CWE ID. */
export function groupByCwe(findings: SecurityFinding[]): Record<string, number> {
  const out: Record<string, number> = {};
  for (const f of findings) {
    for (const cwe of f.cwe) {
      out[cwe] = (out[cwe] ?? 0) + 1;
    }
  }
  return Object.fromEntries(Object.entries(out).sort((a, b) => b[1] - a[1]));
}

/** Count findings grouped by severity. */
export function groupBySeverity(findings: SecurityFinding[]): Record<string, number> {
  const order = ["critical", "high", "medium", "low", "info"] as const;
  const out: Record<string, number> = Object.fromEntries(order.map((s) => [s, 0]));
  for (const f of findings) {
    out[f.severity] = (out[f.severity] ?? 0) + 1;
  }
  return out;
}

/** Top-N most frequent rules (by ruleId). */
export function topRules(findings: SecurityFinding[], n = 10): { ruleId: string; count: number }[] {
  const counts: Record<string, number> = {};
  for (const f of findings) {
    counts[f.ruleId] = (counts[f.ruleId] ?? 0) + 1;
  }
  return Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, n)
    .map(([ruleId, count]) => ({ ruleId, count }));
}

export interface ComplianceSummary {
  total: number;
  bySeverity: Record<string, number>;
  byOwasp: Record<string, number>;
  byCwe: Record<string, number>;
  topRules: { ruleId: string; count: number }[];
}
