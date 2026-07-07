/**
 * Compliance engine. Owns the dispatch from "framework" → mapper and produces
 * a stable JSON shape that the `compliance_check` MCP tool can return.
 */
import type { SecurityFinding } from "../core/finding.js";
import { groupByOwasp } from "./owasp-mapper.js";
import { groupByApiOwasp } from "./api-security-mapper.js";

export type ComplianceFramework = "owasp-top-10" | "owasp-api-top-10" | "cwe";

export interface ComplianceReport {
  framework: ComplianceFramework;
  total: number;
  groups: Record<string, { count: number; findingIds: string[] }>;
}

export function runCompliance(
  findings: SecurityFinding[],
  framework: ComplianceFramework
): ComplianceReport {
  if (framework === "owasp-top-10") {
    const grouped = groupByOwasp(findings);
    return finalize("owasp-top-10", grouped, findings);
  }
  if (framework === "owasp-api-top-10") {
    const grouped = groupByApiOwasp(findings);
    return finalize("owasp-api-top-10", grouped, findings);
  }
  // cwe: bucket by primary CWE id
  const out: Record<string, SecurityFinding[]> = {};
  for (const f of findings) {
    const k = f.cwe[0] ?? "cwe-unknown";
    (out[k] ||= []).push(f);
  }
  return finalize("cwe", out, findings);
}

function finalize(
  framework: ComplianceFramework,
  grouped: Record<string, SecurityFinding[]>,
  findings: SecurityFinding[]
): ComplianceReport {
  const groups: Record<string, { count: number; findingIds: string[] }> = {};
  for (const [k, items] of Object.entries(grouped)) {
    groups[k] = { count: items.length, findingIds: items.map((f) => f.fingerprint) };
  }
  return { framework, total: findings.length, groups };
}
