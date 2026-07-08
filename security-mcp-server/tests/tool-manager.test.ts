import { describe, it, expect, beforeAll, afterAll, beforeEach, vi, type Mock } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, chmodSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, sep } from "node:path";
import type { Logger } from "pino";

// We mock `../src/util/shell.js` so we can simulate `which`/`where`
// without touching the real PATH. Everything else in the manager is real.
vi.mock("../src/util/shell.js", async (importOriginal) => {
  const mod = (await importOriginal()) as Record<string, unknown>;
  return {
    ...mod,
    which: vi.fn(async (_bin: string) => null),
  };
});

import { which } from "../src/util/shell.js";
import {
  ToolManager,
  defaultToolSpecs,
  type ResolvedTool,
  type ToolSpec,
} from "../src/scanners/tool-manager.js";

const mockedWhich = which as unknown as Mock<(bin: string) => Promise<string | null>>;

/** Drop a tiny executable script in `dir/<name>` and return its path.
 *
 * POSIX: a `#!/bin/sh` script that prints a version and exits.
 * Windows: a `.cmd` file in the same dir, with the same basename, that
 *   `echo`s the version. We do not create a file with the bare `name`
 *   (no extension) on Windows because the OS refuses to execute a file
 *   without a recognized extension — instead, callers should ask for
 *   `name` from a directory and rely on the manager's
 *   `candidateNames` to find the `.cmd` variant. For env-override
 *   tests we always pass the full `.cmd` path directly, so the
 *   `.cmd` extension is the only artifact we need.
 */
function dropFakeBin(
  dir: string,
  name: string,
  versionOutput: string = `${name} 9.9.9`,
  exitCode: number = 0,
): string {
  if (process.platform === "win32") {
    const path = join(dir, `${name}.cmd`);
    // `@echo off` then echo the version and exit. `echo` is a builtin
    // so we don't need any external binary on PATH.
    const body = `@echo off\r\necho ${versionOutput}\r\nexit /B ${exitCode}\r\n`;
    writeFileSync(path, body, { encoding: "utf8" });
    return path;
  }
  const path = join(dir, name);
  const body = `#!/bin/sh\nprintf '%s\\n' '${versionOutput}'\nexit ${exitCode}\n`;
  writeFileSync(path, body, { encoding: "utf8", mode: 0o755 });
  chmodSync(path, 0o755);
  return path;
}

function silentLogger(): Logger {
  return {
    info: () => {},
    warn: () => {},
    error: () => {},
    debug: () => {},
    trace: () => {},
    fatal: () => {},
    child: () => silentLogger(),
    level: "silent",
  } as unknown as Logger;
}

/** A spec subset that only includes one tool, so tests are fast. */
function oneSpec(key: "semgrep" | "gitleaks" | "trivy"): ToolSpec[] {
  return defaultToolSpecs().filter((s) => s.key === key);
}

describe("ToolManager", () => {
  let work: string;
  beforeAll(() => {
    work = mkdtempSync(join(tmpdir(), "sec-mcp-toolmgr-"));
  });
  afterAll(() => {
    if (existsSync(work)) rmSync(work, { recursive: true, force: true });
  });
  beforeEach(() => {
    mockedWhich.mockReset();
    mockedWhich.mockResolvedValue(null);
  });

  it("returns 'ok' when env override points at a real executable", async () => {
    const fakeBin = dropFakeBin(work, "semgrep");
    const tm = new ToolManager({
      specs: oneSpec("semgrep"),
      env: { SEMGREP_PATH: fakeBin },
      logger: silentLogger(),
    });
    const r = await tm.discoverOne("semgrep");
    expect(r.status).toBe("ok");
    expect(r.binaryPath).toBe(fakeBin);
    expect(r.version).toMatch(/semgrep 9\.9\.9/);
    expect(r.resolvedFrom).toBe("env");
    expect(r.available).toBe(true);
  });

  it("prefers env over project-local over PATH", async () => {
    const envDir = join(work, "env");
    const localDir = join(work, "local");
    const pathDir = join(work, "path");
    mkdirSync(envDir, { recursive: true });
    mkdirSync(localDir, { recursive: true });
    mkdirSync(pathDir, { recursive: true });
    const envBin = dropFakeBin(envDir, "semgrep", "semgrep env-1.0");
    const localBin = dropFakeBin(localDir, "semgrep", "semgrep local-1.0");
    const pathBin = dropFakeBin(pathDir, "semgrep", "semgrep path-1.0");
    // PATH `which` would return the third one if the manager ever asked.
    mockedWhich.mockResolvedValue(pathBin);

    const tm = new ToolManager({
      specs: oneSpec("semgrep"),
      env: { SEMGREP_PATH: envBin },
      extraSearchDirs: [localDir],
      projectRoot: pathDir, // <-- where PATH would have searched
      logger: silentLogger(),
    });
    const r = await tm.discoverOne("semgrep");
    expect(r.binaryPath).toBe(envBin);
    expect(r.version).toMatch(/env-1\.0/);
    expect(r.resolvedFrom).toBe("env");
    expect(localBin).toBeTruthy(); // ensure fixture is used even if assertion above were wrong
  });

  it("falls back to extraSearchDirs when env is unset", async () => {
    const dir = join(work, "extras", "tool");
    mkdirSync(dir, { recursive: true });
    const fakeBin = dropFakeBin(dir, "gitleaks", "gitleaks 8.18.0");
    const tm = new ToolManager({
      specs: oneSpec("gitleaks"),
      extraSearchDirs: [dir],
      env: {},
      logger: silentLogger(),
    });
    const r = await tm.discoverOne("gitleaks");
    expect(r.binaryPath).toBe(fakeBin);
    expect(r.resolvedFrom).toBe("project-local");
    expect(r.version).toMatch(/gitleaks 8\.18\.0/);
  });

  it("falls back to PATH via which() when nothing else matches", async () => {
    const pathDir = join(work, "pathonly");
    mkdirSync(pathDir, { recursive: true });
    const fakeBin = dropFakeBin(pathDir, "trivy", "trivy 0.50.0");
    mockedWhich.mockResolvedValue(fakeBin);
    const tm = new ToolManager({
      specs: oneSpec("trivy"),
      env: {},
      projectRoot: work, // no node_modules/.bin, no bin/
      logger: silentLogger(),
    });
    const r = await tm.discoverOne("trivy");
    expect(r.binaryPath).toBe(fakeBin);
    expect(r.resolvedFrom).toBe("path");
    expect(r.version).toMatch(/trivy 0\.50\.0/);
  });

  it("returns 'not_found' with a platform-correct install hint", async () => {
    mockedWhich.mockResolvedValue(null);
    const originalPlatform = process.platform;
    const restore = () => {
      Object.defineProperty(process, "platform", { value: originalPlatform, configurable: true });
    };
    try {
      for (const [plat, mustContain, mustNotContain] of [
        ["darwin", "brew install", "winget"],
        ["win32", "winget", "brew install"],
        ["linux", "apt-get", "winget"],
      ] as const) {
        Object.defineProperty(process, "platform", { value: plat, configurable: true });
        const tm = new ToolManager({
          specs: oneSpec("semgrep"),
          env: {},
          projectRoot: work,
          logger: silentLogger(),
        });
        const r = await tm.discoverOne("semgrep");
        expect(r.status).toBe("not_found");
        expect(r.available).toBe(false);
        expect(r.reason).toContain(mustContain);
        expect(r.reason).not.toContain(mustNotContain);
      }
    } finally {
      restore();
    }
  });

  it("reports 'version_probe_failed' when the binary exists but --version errors", async () => {
    const brokenDir = join(work, "broken");
    mkdirSync(brokenDir, { recursive: true });
    const fakeBin = dropFakeBin(brokenDir, "semgrep", "junk", 2);
    const tm = new ToolManager({
      specs: oneSpec("semgrep"),
      env: { SEMGREP_PATH: fakeBin },
      logger: silentLogger(),
    });
    const r = await tm.discoverOne("semgrep");
    expect(r.status).toBe("version_probe_failed");
    expect(r.available).toBe(true);
    expect(r.binaryPath).toBe(fakeBin);
    expect(r.version).toBeUndefined();
  });

  it("validateOrThrow throws ScannerDependencyMissingError listing every missing tool", async () => {
    mockedWhich.mockResolvedValue(null);
    const tm = new ToolManager({
      env: {},
      projectRoot: work,
      failFast: true,
      logger: silentLogger(),
    });
    await expect(tm.validateOrThrow()).rejects.toThrow(/scanner/i);
    await expect(tm.validateOrThrow()).rejects.toThrow(/semgrep/);
    await expect(tm.validateOrThrow()).rejects.toThrow(/gitleaks/);
    await expect(tm.validateOrThrow()).rejects.toThrow(/trivy/);
  });

  it("validateOrThrow returns the resolved list when failFast is off (default)", async () => {
    mockedWhich.mockResolvedValue(null);
    const tm = new ToolManager({
      env: {},
      projectRoot: work,
      logger: silentLogger(),
    });
    const all = await tm.validateOrThrow();
    expect(all).toHaveLength(3);
    expect(all.every((r) => !r.available)).toBe(true);
  });

  it("initialise() logs one info line per tool with structured fields", async () => {
    mockedWhich.mockResolvedValue(null);
    const seen: Array<Record<string, unknown>> = [];
    const capturingLogger: Logger = {
      info: (obj: unknown) => {
        seen.push(obj as Record<string, unknown>);
      },
      warn: () => {},
      error: () => {},
      debug: () => {},
      trace: () => {},
      fatal: () => {},
      child: () => capturingLogger,
      level: "info",
    } as unknown as Logger;
    const tm = new ToolManager({
      env: {},
      projectRoot: work,
      logger: capturingLogger,
    });
    await tm.initialise();
    expect(seen).toHaveLength(3);
    const keys = seen.map((s) => s.tool);
    expect(keys).toEqual(expect.arrayContaining(["semgrep", "gitleaks", "trivy"]));
    for (const entry of seen) {
      expect(entry).toHaveProperty("status");
      expect(entry).toHaveProperty("binaryPath");
      expect(entry).toHaveProperty("resolvedFrom");
      expect(entry).toHaveProperty("version");
      expect(entry).toHaveProperty("reason");
    }
  });

  it("caches results so a second discoverOne() does not re-spawn --version", async () => {
    const fakeBin = dropFakeBin(work, "semgrep", "semgrep 1.2.3");
    const tm = new ToolManager({
      specs: oneSpec("semgrep"),
      env: { SEMGREP_PATH: fakeBin },
      logger: silentLogger(),
    });
    const a = await tm.discoverOne("semgrep");
    const b = await tm.discoverOne("semgrep");
    // Same object identity ⇒ same cached reference.
    expect(a).toBe(b);
  });

  it("discoverAll() returns one result per spec, in declaration order", async () => {
    mockedWhich.mockResolvedValue(null);
    const tm = new ToolManager({
      env: {},
      projectRoot: work,
      logger: silentLogger(),
    });
    const all = await tm.discoverAll();
    expect(all.map((r) => r.key)).toEqual(["semgrep", "gitleaks", "trivy"]);
  });

  it("does not crash when a ToolSpec's env var points at a non-existent file", async () => {
    const tm = new ToolManager({
      specs: oneSpec("semgrep"),
      env: { SEMGREP_PATH: join(work, "no-such-file" + sep + "semgrep") },
      logger: silentLogger(),
    });
    const r = await tm.discoverOne("semgrep");
    expect(r.available).toBe(false);
    expect(r.status).toBe("not_executable");
    expect(r.reason).toMatch(/not executable/);
  });

  it("candidate naming matches the spec (semgrep/gitleaks/trivy across all platforms)", () => {
    const specs = defaultToolSpecs();
    for (const s of specs) {
      // Each spec carries exactly one canonical binary name on POSIX
      // and a Windows alias list on win32; the test documents the
      // expected set so any future rename is a deliberate change
      // caught at code-review time.
      expect(["semgrep", "gitleaks", "trivy"]).toContain(s.key);
      if (process.platform === "win32") {
        expect(s.candidateNames.length).toBeGreaterThanOrEqual(2);
        // The first candidate is the platform-native binary extension
        // (`.exe`), so a fresh release ZIP install is found first.
        expect(s.candidateNames[0]).toBe(`${s.key}.exe`);
        // `.cmd` and the bare name are accepted for shim wrappers and
        // for `npm install` of wrapper packages.
        expect(s.candidateNames).toContain(`${s.key}.cmd`);
        expect(s.candidateNames).toContain(s.key);
      } else {
        expect(s.candidateNames).toEqual([s.key]);
      }
    }
  });

  it("ResolvedTool is fully populated on success", async () => {
    const fakeBin = dropFakeBin(work, "trivy", "trivy 0.55.0");
    const tm = new ToolManager({
      specs: oneSpec("trivy"),
      env: { TRIVY_PATH: fakeBin },
      logger: silentLogger(),
    });
    const r: ResolvedTool = await tm.discoverOne("trivy");
    expect(r).toMatchObject({
      key: "trivy",
      binaryPath: fakeBin,
      available: true,
      status: "ok",
      resolvedFrom: "env",
    });
    expect(r.version).toBeDefined();
    expect(r.reason).toBeDefined();
  });
});
