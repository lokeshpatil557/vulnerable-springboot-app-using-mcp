/**
 * OWASP API Security Top 10 (2023) mapper.
 */
import type { SecurityFinding } from "../core/finding.js";

export type ApiOwaspCategory =
  | "API1:2023-Broken Object Level Authorization"
  | "API2:2023-Broken Authentication"
  | "API3:2023-Broken Object Property Level Authorization"
  | "API4:2023-Unrestricted Resource Consumption"
  | "API5:2023-Broken Function Level Authorization"
  | "API6:2023-Unrestricted Access to Sensitive Business Flows"
  | "API7:2023-Server Side Request Forgery"
  | "API8:2023-Security Misconfiguration"
  | "API9:2023-Improper Inventory Management"
  | "API10:2023-Unsafe Consumption of APIs";

const API_RULES: Array<{ id: string; cat: ApiOwaspCategory; re: RegExp }> = [
  { id: "API1", cat: "API1:2023-Broken Object Level Authorization", re: /object.?level|authoriz/i },
  { id: "API2", cat: "API2:2023-Broken Authentication", re: /authentic|session|jwt|password/i },
  { id: "API3", cat: "API3:2023-Broken Object Property Level Authorization", re: /mass.?assignment|property.?level/i },
  { id: "API4", cat: "API4:2023-Unrestricted Resource Consumption", re: /rate.?limit|resource.?consump|dos/i },
  { id: "API5", cat: "API5:2023-Broken Function Level Authorization", re: /function.?level|admin/i },
  { id: "API6", cat: "API6:2023-Unrestricted Access to Sensitive Business Flows", re: /business.?flow|spam/i },
  { id: "API7", cat: "API7:2023-Server Side Request Forgery", re: /ssrf/i },
  { id: "API8", cat: "API8:2023-Security Misconfiguration", re: /misconfig|cors|debug/i },
  { id: "API9", cat: "API9:2023-Improper Inventory Management", re: /inventory|shadow/i },
  { id: "API10", cat: "API10:2023-Unsafe Consumption of APIs", re: /unsafe.?consump|third.?party/i },
];

export function mapToApiOwasp(finding: SecurityFinding): ApiOwaspCategory | "other" {
  const haystack = `${finding.ruleId} ${finding.message} ${finding.category}`;
  for (const r of API_RULES) if (r.re.test(haystack)) return r.cat;
  return "other";
}

export function groupByApiOwasp(findings: SecurityFinding[]): Record<ApiOwaspCategory | "other", SecurityFinding[]> {
  const out: Record<string, SecurityFinding[]> = {};
  for (const f of findings) {
    const k = mapToApiOwasp(f);
    (out[k] ||= []).push(f);
  }
  return out as Record<ApiOwaspCategory | "other", SecurityFinding[]>;
}
