/**
 * OWASP Top 10 (2021) mapper. Maps rule IDs / categories to the canonical
 * OWASP label. Anything we don't recognize is bucketed under "other".
 */
import type { SecurityFinding } from "../core/finding.js";

export type OwaspCategory =
  | "A01:2021-Broken Access Control"
  | "A02:2021-Cryptographic Failures"
  | "A03:2021-Injection"
  | "A04:2021-Insecure Design"
  | "A05:2021-Security Misconfiguration"
  | "A06:2021-Vulnerable and Outdated Components"
  | "A07:2021-Identification and Authentication Failures"
  | "A08:2021-Software and Data Integrity Failures"
  | "A09:2021-Security Logging and Monitoring Failures"
  | "A10:2021-Server-Side Request Forgery";

const RULES: Array<{ id: string; owasp: OwaspCategory; keywords: RegExp[] }> = [
  { id: "A01", owasp: "A01:2021-Broken Access Control", keywords: [/auth.?z/i, /authoriz/i, /access.?control/i] },
  { id: "A02", owasp: "A02:2021-Cryptographic Failures", keywords: [/crypto/i, /md5|sha1/i, /cipher/i] },
  { id: "A03", owasp: "A03:2021-Injection", keywords: [/sql.?inject/i, /xss/i, /command.?inject/i, /ldap.?inject/i, /ssti/i] },
  { id: "A04", owasp: "A04:2021-Insecure Design", keywords: [/insecure.?design/i, /threat.?model/i] },
  { id: "A05", owasp: "A05:2021-Security Misconfiguration", keywords: [/misconfig/i, /cors/i, /debug/i, /default.?credential/i] },
  { id: "A06", owasp: "A06:2021-Vulnerable and Outdated Components", keywords: [/vulnerab|cve/i, /outdated/i] },
  { id: "A07", owasp: "A07:2021-Identification and Authentication Failures", keywords: [/auth/i, /session/i, /jwt/i, /password/i] },
  { id: "A08", owasp: "A08:2021-Software and Data Integrity Failures", keywords: [/deserial/i, /integrity/i, /signature/i] },
  { id: "A09", owasp: "A09:2021-Security Logging and Monitoring Failures", keywords: [/log/i, /monitoring/i, /audit/i] },
  { id: "A10", owasp: "A10:2021-Server-Side Request Forgery", keywords: [/ssrf/i] },
];

export function mapToOwasp(finding: SecurityFinding): OwaspCategory | "other" {
  if (finding.owasp && finding.owasp.length) {
    const tag = finding.owasp[0];
    const found = RULES.find((r) => tag.toUpperCase().startsWith(r.id));
    if (found) return found.owasp;
  }
  const haystack = `${finding.ruleId} ${finding.message} ${finding.category}`;
  for (const r of RULES) {
    if (r.keywords.some((re) => re.test(haystack))) return r.owasp;
  }
  return "other";
}

export function groupByOwasp(findings: SecurityFinding[]): Record<OwaspCategory | "other", SecurityFinding[]> {
  const out: Record<string, SecurityFinding[]> = {};
  for (const f of findings) {
    const k = mapToOwasp(f);
    (out[k] ||= []).push(f);
  }
  return out as Record<OwaspCategory | "other", SecurityFinding[]>;
}
