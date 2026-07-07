import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { applyWithBackup, rollback } from "../src/diff.js";

describe("diff.applyWithBackup + rollback", () => {
  let repo: string;

  beforeAll(() => {
    repo = mkdtempSync(join(tmpdir(), "sec-mcp-apply-"));
    writeFileSync(join(repo, "App.java"), "old contents");
  });

  afterAll(() => {
    rmSync(repo, { recursive: true, force: true });
  });

  it("creates a backup and writes new contents", async () => {
    const target = join(repo, "App.java");
    const res = await applyWithBackup(repo, target, "new contents");
    expect(res.backupPath).toContain(".security-mcp/backups/");
    expect(readFileSync(target, "utf8")).toBe("new contents");
    expect(readFileSync(res.backupPath, "utf8")).toBe("old contents");

    // Roll back.
    const rb = await rollback(repo, target, res.backupPath, res.sha256Before);
    expect(rb.rolledBack).toBe(true);
    expect(readFileSync(target, "utf8")).toBe("old contents");
  });

  it("refuses to roll back when current hash no longer matches", async () => {
    const target = join(repo, "App.java");
    const res = await applyWithBackup(repo, target, "v2");
    // Tamper with the file after apply.
    writeFileSync(target, "v3");
    const rb = await rollback(repo, target, res.backupPath, res.sha256Before);
    expect(rb.rolledBack).toBe(false);
    expect(rb.reason).toMatch(/no longer matches/);
  });
});
