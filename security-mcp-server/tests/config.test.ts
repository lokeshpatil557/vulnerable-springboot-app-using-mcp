import { describe, it, expect } from "vitest";
import { loadConfig, defaultConfig } from "../src/config.js";

describe("config", () => {
  it("applies defaults for an empty environment", () => {
    const c = loadConfig({});
    expect(c.repoRoot).toBe("auto");
    expect(c.logLevel).toBe("info");
    expect(c.scanTimeoutMs).toBe(300_000);
    expect(c.maxConcurrentScanners).toBe(2);
    expect(c.auditLogPath).toBe(".security-mcp/audit.jsonl");
    expect(c.redactInReports).toBe(true);
  });

  it("respects env overrides", () => {
    const c = loadConfig({
      REPO_ROOT: "/x",
      LOG_LEVEL: "debug",
      SCAN_TIMEOUT_MS: "60000",
      MAX_CONCURRENT_SCANNERS: "4",
      SEMGREP_PATH: "/opt/semgrep",
      INCLUDE_RULE_SETS: "p/owasp-top-ten,p/secrets",
      REDACT_IN_REPORTS: "false",
    });
    expect(c.repoRoot).toBe("/x");
    expect(c.logLevel).toBe("debug");
    expect(c.scanTimeoutMs).toBe(60_000);
    expect(c.maxConcurrentScanners).toBe(4);
    expect(c.perScannerBinaries.semgrep).toBe("/opt/semgrep");
    expect(c.includeRuleSets).toEqual(["p/owasp-top-ten", "p/secrets"]);
    expect(c.redactInReports).toBe(false);
  });

  it("defaultConfig returns the same as empty env", () => {
    expect(defaultConfig()).toEqual(loadConfig({}));
  });
});
