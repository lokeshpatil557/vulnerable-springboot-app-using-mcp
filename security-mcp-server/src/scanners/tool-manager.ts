/**
 * ToolManager — discovers, version-probes, and reports availability for
 * the three external scanner CLIs the MCP server depends on
 * (`semgrep`, `gitleaks`, `trivy`).
 *
 * Goals
 * -----
 * - Centralise the "is this binary installed?" concern that's currently
 *   spread across `src/util/shell.ts#which` and the per-adapter
 *   `checkAvailable()` calls in `src/scanners/base.ts`.
 * - Make resolution cross-platform **without** hardcoding absolute paths.
 *   Order: explicit env override → project-local (`./node_modules/.bin`,
 *   `./bin`) → `PATH` (via `which` on POSIX, `where` on Windows).
 * - Distinguish "not installed" from "installed but broken" so the
 *   orchestrator and the per-tool `unavailable[]` API can give the
 *   developer a useful install hint.
 * - Stay compatible with the existing graceful-degradation design: by
 *   default, missing tools are *reported*; the fail-fast mode is opt-in
 *   via `SCANNER_FAIL_FAST=1` (or `ToolManager` constructor flag).
 *
 * Threading
 * ---------
 * All work happens inside the Node.js event loop. There is no native
 * binding and no parallel I/O — the bottleneck is `which`/`where` and
 * `--version` execs, both of which already use `execa` with a timeout.
 *
 * The result of `discoverAll()` is memoised on the instance, so calling
 * it (or `discoverOne()` for a known key) repeatedly is cheap. Tests
 * rely on this — see `tests/tool-manager.test.ts`.
 */
import { execa } from "execa";
import { access, constants as fsConstants } from "node:fs/promises";
import { existsSync } from "node:fs";
import { isAbsolute, join, resolve, sep } from "node:path";
import type { Logger } from "pino";
import { which } from "../util/shell.js";
import { ScannerDependencyMissingError } from "../errors.js";

export type ScannerKey = "semgrep" | "gitleaks" | "trivy";

/** Where a binary was ultimately resolved from. `null` = not found. */
export type ToolSource = "env" | "project-local" | "path" | null;

/** Outcome of a probe for a single tool. */
export type ToolStatus =
  | "ok"
  | "not_found"
  | "version_probe_failed"
  | "not_executable";

/** Static description of a tool the manager knows how to discover. */
export interface ToolSpec {
  /** Logical id used by adapters and the registry. */
  key: ScannerKey;
  /** Human-readable display name (used in logs and install hints). */
  displayName: string;
  /** Binaries we will try, in order. First match wins. */
  candidateNames: string[];
  /** Env vars that override the resolved path. First non-empty wins. */
  envVars: string[];
  /** Informational only; we never block on version. */
  minVersion?: string;
}

/** Result of a discovery probe for one tool. */
export interface ResolvedTool {
  key: ScannerKey;
  /** Absolute path to the resolved binary, or `null` if not found. */
  binaryPath: string | null;
  /** `true` if we believe the binary will run. */
  available: boolean;
  /** First line of `<bin> --version`, e.g. "semgrep 1.95.0". */
  version: string | undefined;
  status: ToolStatus;
  /** Human-readable message for logs and the `unavailable` API. */
  reason: string;
  /** Where we found the binary, or `null` if `not_found`. */
  resolvedFrom: ToolSource;
}

export interface ToolManagerOptions {
  /** Override the registry. Defaults to `defaultToolSpecs()`. */
  specs?: ToolSpec[];
  /** Extra absolute directories to search between env and PATH. */
  extraSearchDirs?: string[];
  /** Project root used to compute the project-local search dirs. */
  projectRoot?: string;
  /** Process env to read overrides from. Defaults to `process.env`. */
  env?: NodeJS.ProcessEnv;
  /** When `true`, `validateOrThrow()` throws if any tool is unavailable. */
  failFast?: boolean;
  /** Logger — pino. */
  logger: Logger;
}

/** Return the canonical registry of all tools the MCP server depends on. */
export function defaultToolSpecs(): ToolSpec[] {
  // On Windows, `execa` (via Node's `child_process.spawn`) can launch
  // `.cmd` / `.bat` files directly when the path includes the
  // extension. Real installs usually land as `.exe` (e.g. the
  // gitleaks Windows release is `gitleaks.exe`), so we list both:
  // the bare name as a courtesy for shim wrappers, plus the
  // platform-native extension.
  const isWin = process.platform === "win32";
  return [
    {
      key: "semgrep",
      displayName: "Semgrep (SAST)",
      candidateNames: isWin ? ["semgrep.exe", "semgrep.cmd", "semgrep"] : ["semgrep"],
      envVars: ["SEMGREP_PATH"],
      minVersion: "1.40.0",
    },
    {
      key: "gitleaks",
      displayName: "Gitleaks (secret detection)",
      candidateNames: isWin ? ["gitleaks.exe", "gitleaks.cmd", "gitleaks"] : ["gitleaks"],
      envVars: ["GITLEAKS_PATH"],
      minVersion: "8.18.0",
    },
    {
      key: "trivy",
      displayName: "Trivy (vuln / IaC / container / SBOM)",
      candidateNames: isWin ? ["trivy.exe", "trivy.cmd", "trivy"] : ["trivy"],
      envVars: ["TRIVY_PATH"],
      minVersion: "0.50.0",
    },
  ];
}

/**
 * Per-tool, per-platform install hint. We surface the *most likely*
 * package-manager install line; users on an unusual distro may need to
 * adapt. The list is intentionally short so the failure message stays
 * scannable.
 */
function installHint(key: ScannerKey, platform: NodeJS.Platform): string {
  const isWin = platform === "win32";
  const isMac = platform === "darwin";
  const map: Record<ScannerKey, { brew: string; apt: string; pip: string; winget: string; scoop: string; choco: string }> = {
    semgrep: {
      brew: "brew install semgrep",
      apt: "sudo apt-get install -y python3-pip && pip3 install --user semgrep",
      pip: "pip3 install --user 'semgrep>=1.40'",
      winget: "winget install --id Semgrep.Semgrep",
      scoop: "scoop install semgrep",
      choco: "choco install semgrep",
    },
    gitleaks: {
      brew: "brew install gitleaks",
      apt: "sudo apt-get install -y gitleaks  # or download from https://github.com/gitleaks/gitleaks/releases",
      pip: "Download a release binary from https://github.com/gitleaks/gitleaks/releases",
      winget: "winget install --id GitHub.gitleaks",
      scoop: "scoop install gitleaks",
      choco: "choco install gitleaks",
    },
    trivy: {
      brew: "brew install trivy",
      apt: "sudo apt-get install -y wget apt-transport-https gnupg lsb-release && wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo gpg --dearmor -o /usr/share/keyrings/trivy.gpg && echo 'deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main' | sudo tee /etc/apt/sources.list.d/trivy.list && sudo apt-get update && sudo apt-get install -y trivy",
      pip: "Download a release binary from https://github.com/aquasecurity/trivy/releases",
      winget: "winget install --id AquaSecurity.Trivy",
      scoop: "scoop install trivy",
      choco: "choco install trivy",
    },
  };
  const m = map[key];
  if (isWin) {
    return `install via: ${m.winget}  # or  ${m.scoop}  # or  ${m.choco}`;
  }
  if (isMac) {
    return `install via: ${m.brew}  # or  ${m.pip} (semgrep only)`;
  }
  // Linux / other POSIX.
  return `install via: ${m.apt}  # or  ${m.brew} (if Homebrew is available)`;
}

/**
 * Run a child process synchronously enough for our needs (execa is
 * already a dependency). We swallow "binary not found" errors and turn
 * them into `null` — the manager is the *only* code that decides what
 * a missing binary means.
 */
async function safeExec(
  bin: string,
  args: string[],
  timeoutMs: number,
): Promise<{ exitCode: number; stdout: string; stderr: string } | null> {
  try {
    const res = await execa(bin, args, {
      reject: false,
      timeout: timeoutMs,
      // shell:false is execa's default; explicit for clarity.
      shell: false,
      windowsHide: true,
    });
    return {
      exitCode: res.exitCode ?? -1,
      stdout: typeof res.stdout === "string" ? res.stdout : "",
      stderr: typeof res.stderr === "string" ? res.stderr : "",
    };
  } catch {
    return null;
  }
}

/**
 * Is `path` something we can spawn? On POSIX this is an `X_OK` check
 * (mirrors what `execve` would do). On Windows, `access` with `X_OK`
 * is a no-op, so we fall back to "exists and isn't a directory".
 */
async function isExecutable(path: string): Promise<boolean> {
  if (!existsSync(path)) return false;
  if (process.platform === "win32") {
    // Windows resolves PATHEXT for us; existence is enough.
    return true;
  }
  try {
    await access(path, fsConstants.X_OK);
    return true;
  } catch {
    return false;
  }
}

/**
 * The ToolManager — see file-level docstring. Designed to be constructed
 * once at boot and reused; the result of `discoverAll()` is memoised.
 */
export class ToolManager {
  private readonly specs: ToolSpec[];
  private readonly extraSearchDirs: string[];
  private readonly projectRoot: string;
  private readonly env: NodeJS.ProcessEnv;
  private readonly failFast: boolean;
  private readonly logger: Logger;
  private readonly cache = new Map<ScannerKey, ResolvedTool>();
  private initialised = false;

  constructor(opts: ToolManagerOptions) {
    this.specs = opts.specs ?? defaultToolSpecs();
    this.extraSearchDirs = (opts.extraSearchDirs ?? []).map((p) => resolve(p));
    this.projectRoot = resolve(opts.projectRoot ?? process.cwd());
    this.env = opts.env ?? process.env;
    this.failFast = opts.failFast ?? false;
    this.logger = opts.logger;
  }

  /** Return the specs this manager was constructed with. */
  getSpecs(): readonly ToolSpec[] {
    return this.specs;
  }

  /** Discover a single tool. Result is cached. */
  async discoverOne(key: ScannerKey): Promise<ResolvedTool> {
    const cached = this.cache.get(key);
    if (cached) return cached;
    const spec = this.specs.find((s) => s.key === key);
    if (!spec) {
      throw new Error(`ToolManager: unknown scanner key '${key}'`);
    }
    const result = await this.resolveSpec(spec);
    this.cache.set(key, result);
    return result;
  }

  /** Discover every tool in the registry, in declaration order. */
  async discoverAll(): Promise<ResolvedTool[]> {
    const out: ResolvedTool[] = [];
    for (const spec of this.specs) {
      out.push(await this.discoverOne(spec.key));
    }
    return out;
  }

  /**
   * Throw a typed `ScannerDependencyMissingError` (which extends
   * `ToolUnavailableError`) if any required tool is missing AND the
   * manager was constructed with `failFast: true`. Returns the resolved
   * list otherwise (callers can still inspect `.available` themselves).
   */
  async validateOrThrow(): Promise<ResolvedTool[]> {
    const all = await this.discoverAll();
    const missing = all.filter((r) => !r.available);
    if (missing.length === 0) return all;
    if (!this.failFast) return all;
    throw new ScannerDependencyMissingError(
      missing.map((m) => ({
        key: m.key,
        reason: m.reason,
        binaryPath: m.binaryPath,
        status: m.status,
      })),
    );
  }

  /**
   * Idempotent: discover + log a single info line per tool. Designed
   * to be called from the orchestrator's constructor. Returns the
   * resolved list so the orchestrator can feed it into adapter
   * constructors.
   */
  async initialise(): Promise<ResolvedTool[]> {
    if (this.initialised) {
      return this.discoverAll();
    }
    const all = await this.discoverAll();
    for (const r of all) {
      this.logger.info(
        {
          tool: r.key,
          status: r.status,
          binaryPath: r.binaryPath,
          resolvedFrom: r.resolvedFrom,
          version: r.version,
          reason: r.reason,
        },
        "scanner resolved",
      );
    }
    this.initialised = true;
    return all;
  }

  /** ------------------------------------------------------------------------ */
  /**  Private resolution algorithm — see file-level docstring for the order. */
  /** ------------------------------------------------------------------------ */

  private async resolveSpec(spec: ToolSpec): Promise<ResolvedTool> {
    // 1. Env override.
    for (const envName of spec.envVars) {
      const raw = (this.env[envName] ?? "").trim();
      if (!raw) continue;
      const abs = isAbsolute(raw) ? raw : resolve(this.projectRoot, raw);
      if (await isExecutable(abs)) {
        return this.probeVersion(spec, abs, "env");
      }
      return {
        key: spec.key,
        binaryPath: abs,
        available: false,
        version: undefined,
        status: "not_executable",
        reason: `${envName}='${raw}' is set but '${abs}' is not executable`,
        resolvedFrom: "env",
      };
    }

    // 2. Project-local + extra search dirs.
    const localHits = await this.searchLocalDirs(spec);
    if (localHits) {
      return this.probeVersion(spec, localHits, "project-local");
    }

    // 3. PATH (via `which` / `where`).
    for (const name of spec.candidateNames) {
      const found = await which(name);
      if (found) {
        return this.probeVersion(spec, found, "path");
      }
    }

    // 4. Not found anywhere.
    return {
      key: spec.key,
      binaryPath: null,
      available: false,
      version: undefined,
      status: "not_found",
      reason: installHint(spec.key, process.platform),
      resolvedFrom: null,
    };
  }

  /**
   * Project-local + extra search dirs. We do **not** trust the `PATH`
   * variable here — only literal directories the manager was told
   * about. Order:
   *   a. `extraSearchDirs` (in order, deduped against the project-local list).
   *   b. `<projectRoot>/node_modules/.bin/<name>`  (npm-managed).
   *   c. `<projectRoot>/bin/<name>`                  (in-repo vendoring).
   */
  private async searchLocalDirs(spec: ToolSpec): Promise<string | null> {
    const seen = new Set<string>();
    const candidates: string[] = [];
    for (const dir of this.extraSearchDirs) {
      for (const name of spec.candidateNames) {
        const p = join(dir, name);
        if (seen.has(p)) continue;
        seen.add(p);
        candidates.push(p);
      }
    }
    const localRoots = [
      join(this.projectRoot, "node_modules", ".bin"),
      join(this.projectRoot, "bin"),
    ];
    for (const root of localRoots) {
      for (const name of spec.candidateNames) {
        const p = join(root, name);
        if (seen.has(p)) continue;
        seen.add(p);
        candidates.push(p);
      }
    }
    for (const p of candidates) {
      if (await isExecutable(p)) return p;
    }
    return null;
  }

  /**
   * Probe a resolved binary by running `<bin> --version` and reading
   * the first line. 5-second timeout. We treat timeout / non-zero exit
   * as `version_probe_failed` rather than a hard failure — the binary
   * is still considered "available" for the caller's purposes; the
   * version field stays `undefined` and the reason explains why.
   */
  private async probeVersion(
    spec: ToolSpec,
    absPath: string,
    resolvedFrom: Exclude<ToolSource, null>,
  ): Promise<ResolvedTool> {
    const res = await safeExec(absPath, ["--version"], 5_000);
    if (!res || res.exitCode !== 0) {
      return {
        key: spec.key,
        binaryPath: absPath,
        available: true,
        version: undefined,
        status: "version_probe_failed",
        reason: `binary exists at ${absPath} but '${spec.candidateNames[0]} --version' failed (exit ${res?.exitCode ?? -1})`,
        resolvedFrom,
      };
    }
    const firstLine = (res.stdout || res.stderr).split(/\r?\n/)[0]?.trim();
    return {
      key: spec.key,
      binaryPath: absPath,
      available: true,
      version: firstLine || undefined,
      status: "ok",
      reason: firstLine ? `resolved via ${resolvedFrom}: ${absPath}` : `resolved via ${resolvedFrom}: ${absPath}`,
      resolvedFrom,
    };
  }
}

// Re-export so tests can stub `which` via the same import the manager uses.
export { which };

// Quiet "unused" warnings for constants kept for documentation / future use.
void sep;
