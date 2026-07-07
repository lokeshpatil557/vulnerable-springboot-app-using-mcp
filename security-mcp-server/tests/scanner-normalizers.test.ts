import { describe, it, expect } from "vitest";
import { buildFromSemgrep, buildFromGitleaks, buildFromTrivyVuln } from "../src/scanners/base.js";

describe("scanner normalizers", () => {
  it("buildFromSemgrep maps a semgrep result row", () => {
    const row = {
      check_id: "java.lang.security.audit.formatted-sql-string",
      path: "src/main/java/X.java",
      start: { line: 10, col: 1 },
      end: { line: 10, col: 30 },
      extra: {
        message: "User input in SQL string",
        severity: "ERROR",
        metadata: { cwe: ["CWE-89"], owasp: ["A03:2021"] },
        fix: "--- a\n+++ b\n-old\n+new",
        fix_description: "Use a PreparedStatement",
      },
    };
    const f = buildFromSemgrep(row, "1.0.0", "src/main/java/X.java");
    expect(f.ruleId).toBe("java.lang.security.audit.formatted-sql-string");
    expect(f.severity).toBe("high");
    expect(f.cwe).toEqual(["CWE-89"]);
    expect(f.owasp).toEqual(["A03:2021"]);
    expect(f.fix?.description).toContain("PreparedStatement");
  });

  it("buildFromGitleaks masks the secret value", () => {
    const row = {
      RuleID: "aws-access-token",
      File: "config/app.yml",
      StartLine: 5,
      EndLine: 5,
      Secret: "AKIAIOSFODNN7EXAMPLE",
    };
    const f = buildFromGitleaks(row, "8.18.0", "config/app.yml");
    expect(f.severity).toBe("high");
    expect(f.category).toBe("secret");
    expect(f.message).toMatch(/\*{4}MPLE/); // last 4 chars visible
    expect(f.message).not.toContain("AKIAIOSFODNN7EXAMPLE");
  });

  it("buildFromTrivyVuln maps a vulnerability row", () => {
    const v = {
      VulnerabilityID: "CVE-2024-0001",
      PkgName: "log4j-core",
      InstalledVersion: "2.14.0",
      FixedVersion: "2.17.0",
      Title: "RCE in log4j",
      Severity: "CRITICAL",
      CweIDs: ["CWE-502"],
    };
    const f = buildFromTrivyVuln(v, "pom.xml", "0.50.0");
    expect(f.severity).toBe("critical");
    expect(f.cve).toEqual(["CVE-2024-0001"]);
    expect(f.cwe).toEqual(["CWE-502"]);
    expect(f.category).toBe("vuln");
  });
});
