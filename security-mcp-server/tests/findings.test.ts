import { describe, it, expect } from "vitest";
import {
  fingerprint,
  severityFromCvss,
  severityFromSemgrep,
  severityFromTrivy,
  maskSecret,
  levelFromSarif,
  severityToLevel,
} from "../src/findings.js";

describe("findings", () => {
  it("fingerprint is stable and 16 chars", () => {
    const f = fingerprint({ ruleId: "r1", path: "a/b", startLine: 10, message: "hi" });
    expect(f).toHaveLength(16);
    expect(f).toBe(fingerprint({ ruleId: "r1", path: "a/b", startLine: 10, message: "hi" }));
    expect(f).not.toBe(fingerprint({ ruleId: "r2", path: "a/b", startLine: 10, message: "hi" }));
  });

  it("severityFromCvss maps CVSS to buckets", () => {
    expect(severityFromCvss(9.5)).toBe("critical");
    expect(severityFromCvss(8.0)).toBe("high");
    expect(severityFromCvss(5.0)).toBe("medium");
    expect(severityFromCvss(3.0)).toBe("low");
    expect(severityFromCvss(0)).toBe("info");
    expect(severityFromCvss(null)).toBe("medium");
  });

  it("severityFromSemgrep maps strings", () => {
    expect(severityFromSemgrep("ERROR")).toBe("high");
    expect(severityFromSemgrep("WARNING")).toBe("medium");
    expect(severityFromSemgrep("INFO")).toBe("low");
    expect(severityFromSemgrep(undefined)).toBe("medium");
  });

  it("severityFromTrivy maps strings", () => {
    expect(severityFromTrivy("CRITICAL")).toBe("critical");
    expect(severityFromTrivy("HIGH")).toBe("high");
    expect(severityFromTrivy("MEDIUM")).toBe("medium");
    expect(severityFromTrivy("LOW")).toBe("low");
    expect(severityFromTrivy("UNKNOWN")).toBe("info");
  });

  it("maskSecret only reveals last 4 chars", () => {
    expect(maskSecret("abcdef123456")).toBe("********3456");
    expect(maskSecret("abcd")).toBe("abcd");
    expect(maskSecret("")).toBe("");
    expect(maskSecret(null)).toBe("");
  });

  it("SARIF level mappings round-trip through severity", () => {
    expect(levelFromSarif("error")).toBe("error");
    expect(levelFromSarif("warning")).toBe("warning");
    expect(levelFromSarif("note")).toBe("note");
    expect(severityToLevel("critical")).toBe("error");
    expect(severityToLevel("medium")).toBe("warning");
    expect(severityToLevel("info")).toBe("note");
  });
});
