import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { resolveRepoRoot, assertInsideRepo, safeJoin, relativeToRepo } from "../src/paths.js";

describe("paths", () => {
  let repo: string;
  let subdir: string;

  beforeAll(() => {
    repo = mkdtempSync(join(tmpdir(), "sec-mcp-paths-"));
    mkdirSync(join(repo, "src"), { recursive: true });
    mkdirSync(join(repo, ".git"), { recursive: true });
    subdir = join(repo, "src", "app");
    mkdirSync(subdir, { recursive: true });
    writeFileSync(join(subdir, "Main.java"), "public class Main {}");
  });

  afterAll(() => {
    rmSync(repo, { recursive: true, force: true });
  });

  it("resolveRepoRoot walks up to the .git directory", () => {
    const found = resolveRepoRoot(subdir);
    expect(found.replace(/\\/g, "/")).toBe(repo.replace(/\\/g, "/"));
  });

  it("resolveRepoRoot throws when there is no .git", () => {
    const orphan = mkdtempSync(join(tmpdir(), "sec-mcp-orphan-"));
    try {
      expect(() => resolveRepoRoot(orphan)).toThrow(/No .git/);
    } finally {
      rmSync(orphan, { recursive: true, force: true });
    }
  });

  it("assertInsideRepo accepts files inside the repo", () => {
    const abs = assertInsideRepo(repo, join("src", "app", "Main.java"));
    expect(abs.endsWith("Main.java")).toBe(true);
  });

  it("assertInsideRepo rejects paths that escape the repo", () => {
    expect(() => assertInsideRepo(repo, join("..", "etc", "passwd"))).toThrow(/outside/);
  });

  it("safeJoin produces a path inside the repo", () => {
    const p = safeJoin(repo, ".security-mcp", "backups", "x");
    expect(p.startsWith(repo)).toBe(true);
  });

  it("relativeToRepo returns the relative path", () => {
    const rel = relativeToRepo(repo, join(subdir, "Main.java"));
    expect(rel.replace(/\\/g, "/")).toBe("src/app/Main.java");
  });
});
