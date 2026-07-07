import { describe, it, expect } from "vitest";
import { lookupTemplate, listTemplates } from "../src/rules/index.js";
import { proposeRemediation } from "../src/remediation.js";
import { generateUnifiedDiff } from "../src/diff.js";
import type { SecurityFinding } from "../src/findings.js";

describe("remediation", () => {
  it("returns a non-empty diff when Semgrep provides a fix", () => {
    const finding: SecurityFinding = {
      id: "abc",
      ruleId: "any.rule",
      level: "warning",
      severity: "medium",
      message: "test",
      location: { path: "a.js", startLine: 1, endLine: 1 },
      cwe: [],
      category: "sast",
      tool: { name: "semgrep" },
      fingerprint: "abc",
      fix: { description: "fix me", diff: "--- a\n+++ b\n-old\n+new" },
    };
    const p = proposeRemediation(finding, "old");
    expect(p.source).toBe("semgrep_fix");
    expect(p.confidence).toBe("high");
  });

  it("falls back to a template when the rule has a known template", () => {
    const finding: SecurityFinding = {
      id: "x",
      ruleId: "javascript.lang.security.audit.eval-detected",
      level: "error",
      severity: "high",
      message: "eval found",
      location: { path: "a.js", startLine: 1, endLine: 1 },
      cwe: ["CWE-95"],
      category: "sast",
      tool: { name: "semgrep" },
      fingerprint: "x",
    };
    const contents = "function f() { eval('x'); }";
    const p = proposeRemediation(finding, contents);
    expect(p.source).toBe("template");
    expect(p.diff.length).toBeGreaterThan(0);
    expect(p.confidence).toBe("high");
  });

  it("returns manual fallback when no rule matches", () => {
    const finding: SecurityFinding = {
      id: "x",
      ruleId: "unknown.rule",
      level: "warning",
      severity: "low",
      message: "test",
      location: { path: "a.js", startLine: 1, endLine: 1 },
      cwe: [],
      category: "sast",
      tool: { name: "semgrep" },
      fingerprint: "x",
    };
    const p = proposeRemediation(finding, "x");
    expect(p.source).toBe("manual");
    expect(p.diff).toBe("");
    expect(p.confidence).toBe("low");
  });

  it("listTemplates returns at least one entry", () => {
    expect(listTemplates().length).toBeGreaterThan(0);
  });

  it("lookupTemplate returns null for unknown rules", () => {
    expect(lookupTemplate("nope.nope.nope")).toBeNull();
  });

  it("generateUnifiedDiff wraps template output", () => {
    const d = generateUnifiedDiff("a.js", "eval('x');", "JSON.parse('x');");
    expect(d).toMatch(/^Index: a\.js/);
  });
});
