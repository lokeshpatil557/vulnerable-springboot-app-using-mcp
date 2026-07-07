import { describe, it, expect } from "vitest";
import { groupByOwasp, groupByCwe, groupBySeverity, topRules } from "../src/compliance.js";
import type { SecurityFinding } from "../src/findings.js";

const finding = (over: Partial<SecurityFinding>): SecurityFinding => ({
  id: "x",
  ruleId: "r",
  level: "warning",
  severity: "medium",
  message: "m",
  location: { path: "a", startLine: 1, endLine: 1 },
  cwe: [],
  category: "sast",
  tool: { name: "semgrep" },
  fingerprint: "x",
  ...over,
});

describe("compliance", () => {
  it("groupBySeverity counts each level", () => {
    const f = [
      finding({ severity: "critical" }),
      finding({ severity: "critical" }),
      finding({ severity: "high" }),
      finding({ severity: "low" }),
    ];
    const r = groupBySeverity(f);
    expect(r.critical).toBe(2);
    expect(r.high).toBe(1);
    expect(r.low).toBe(1);
    expect(r.medium).toBe(0);
    expect(r.info).toBe(0);
  });

  it("groupByOwasp counts each category", () => {
    const f = [
      finding({ owasp: ["A01:2021", "A03:2021"] }),
      finding({ owasp: ["A01:2021"] }),
    ];
    const r = groupByOwasp(f);
    expect(r["A01:2021"]).toBe(2);
    expect(r["A03:2021"]).toBe(1);
  });

  it("groupByCwe counts each CWE", () => {
    const f = [
      finding({ cwe: ["CWE-89", "CWE-79"] }),
      finding({ cwe: ["CWE-89"] }),
    ];
    const r = groupByCwe(f);
    expect(r["CWE-89"]).toBe(2);
    expect(r["CWE-79"]).toBe(1);
  });

  it("topRules returns the most frequent rules", () => {
    const f = [
      finding({ ruleId: "a" }),
      finding({ ruleId: "a" }),
      finding({ ruleId: "a" }),
      finding({ ruleId: "b" }),
      finding({ ruleId: "b" }),
      finding({ ruleId: "c" }),
    ];
    const r = topRules(f, 2);
    expect(r[0]).toEqual({ ruleId: "a", count: 3 });
    expect(r[1]).toEqual({ ruleId: "b", count: 2 });
  });
});
