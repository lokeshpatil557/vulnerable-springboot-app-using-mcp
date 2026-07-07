import { describe, it, expect } from "vitest";
import { groupBySeverity } from "../src/compliance.js";
import { renderMarkdown } from "../src/reports/markdown.js";
import { renderPrDescription } from "../src/reports/pr-description.js";
import type { SecurityFinding } from "../src/findings.js";

const sample: SecurityFinding[] = [
  {
    id: "1",
    ruleId: "java.lang.security.formatted-sql-string",
    level: "error",
    severity: "high",
    message: "Possible SQL injection",
    location: { path: "src/main/java/UserController.java", startLine: 12, endLine: 12 },
    cwe: ["CWE-89"],
    owasp: ["A03:2021 - Injection"],
    category: "sast",
    tool: { name: "semgrep" },
    fingerprint: "1",
  },
  {
    id: "2",
    ruleId: "gitleaks:aws-access-token",
    level: "error",
    severity: "high",
    message: "AWS access key",
    location: { path: "src/main/resources/application.properties", startLine: 4, endLine: 4 },
    cwe: ["CWE-798"],
    owasp: ["A07:2021"],
    category: "secret",
    tool: { name: "gitleaks" },
    fingerprint: "2",
  },
];

const meta = {
  repoRoot: "/repo",
  scannerVersions: { semgrep: "1.0.0", gitleaks: "8.18.0", trivy: "0.50.0" },
  scanId: "scan-1",
  startedAt: "2026-07-06T00:00:00.000Z",
  finishedAt: "2026-07-06T00:00:05.000Z",
  durationMs: 5000,
};

describe("reports/markdown", () => {
  it("renders a header, summary, and severity sections", () => {
    const md = renderMarkdown(sample, meta);
    expect(md).toMatch(/# Security report/);
    expect(md).toMatch(/HIGH \(2\)/);
    expect(md).toMatch(/SQL injection/);
    expect(md).toMatch(/AWS access key/);
    expect(md).toMatch(/OWASP Top 10 coverage/);
  });

  it("groupBySeverity returns ordered buckets", () => {
    const g = groupBySeverity(sample);
    expect(g.high).toBe(2);
  });
});

describe("reports/pr-description", () => {
  it("includes a severity table and top findings", () => {
    const pr = renderPrDescription(sample, meta);
    expect(pr).toMatch(/## Security remediation/);
    expect(pr).toMatch(/high \| 2/);
    expect(pr).toMatch(/Top findings/);
    expect(pr).toMatch(/Fix checklist/);
  });
});
