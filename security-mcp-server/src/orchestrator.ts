/**
 * Security Orchestrator — the single composition root the MCP server hands
 * to every tool. Owns the scanner registry, the static plugin registry, and
 * the remediation engine, plus the resolved target repo path.
 *
 * Keep this class a thin wiring layer: business logic stays in `scanners/`,
 * `plugins/`, and `remediation/`. The orchestrator only:
 *   - constructs the registries
 *   - exposes them as immutable handles
 *   - tracks the resolved `repoRoot` and original `allowedRoot` env inputs
 *   - delegates external-tool discovery to `ToolManager`
 */
import type { Logger } from "pino";
import type { Config } from "./config.js";
import {
  buildScannerRegistry,
  type ScannerRegistry,
  type ScannerId,
} from "./scanners/registry.js";
import {
  ToolManager,
  type ResolvedTool,
} from "./scanners/tool-manager.js";
import { getPlugins } from "./plugins/plugin-registry.js";
import type { StackPlugin } from "./plugins/plugin.interface.js";
import { RemediationEngine } from "./remediation/remediation-engine.js";

export interface SecurityOrchestratorOptions {
  config: Config;
  logger: Logger;
  /** Resolved, absolute, Git-validated repo root. */
  repoRoot: string;
  /**
   * The raw `SECURITY_MCP_ALLOWED_ROOT` or `TARGET_REPO_PATH` value the
   * server was started with. Recorded for diagnostics and the
   * `supported_stacks` tool. May be `null` if neither env var was set.
   */
  allowedRootSource: string | null;
  /**
   * Inject a pre-built `ToolManager`. Used by tests. The orchestrator
   * builds its own (synchronous) instance when this is omitted.
   */
  toolManager?: ToolManager;
}

export class SecurityOrchestrator {
  readonly config: Config;
  readonly logger: Logger;
  readonly repoRoot: string;
  readonly allowedRootSource: string | null;
  readonly scanners: ScannerRegistry;
  readonly plugins: readonly StackPlugin[];
  readonly remediation: RemediationEngine;
  readonly toolManager: ToolManager;
  /** Probe results for every scanner the manager knows about. */
  readonly tools: ResolvedTool[] = [];
  readonly startedAt: number;

  constructor(opts: SecurityOrchestratorOptions) {
    this.config = opts.config;
    this.logger = opts.logger;
    this.repoRoot = opts.repoRoot;
    this.allowedRootSource = opts.allowedRootSource;
    this.startedAt = Date.now();

    // 1. External tool discovery — runs env > project-local > PATH for
    //    every scanner the registry advertises. Synchronous construction,
    //    but `initialise()` (called below) does the actual I/O.
    this.toolManager =
      opts.toolManager ??
      new ToolManager({
        failFast: opts.config.scannerFailFast,
        projectRoot: opts.repoRoot,
        logger: opts.logger,
      });

    // 2. Scanner adapters: Semgrep (SAST), Gitleaks (secret), Trivy (vuln).
    //    We seed them with the *user's* env overrides (if any) — the
    //    ToolManager takes priority and we rewire the adapters below
    //    once we know the resolved paths.
    this.scanners = buildScannerRegistry(opts.config);

    // 3. Static plugin registry — no dynamic imports, see plugin-registry.ts.
    this.plugins = getPlugins();

    // 4. Remediation engine: propose / preview / apply / verify.
    this.remediation = new RemediationEngine();

    opts.logger.info(
      {
        repoRoot: this.repoRoot,
        allowedRootSource: this.allowedRootSource,
        scannerIds: this.scannerIds(),
        pluginIds: this.plugins.map((p) => p.id),
      },
      "security orchestrator initialised",
    );
  }

  /**
   * Run external-tool discovery. Idempotent — calling it more than once
   * is safe and cheap. Designed to be called from the orchestrator's
   * caller (see `index.ts`) so we can fail fast *before* any tool is
   * registered on the MCP server.
   *
   * Throws `ScannerDependencyMissingError` when `config.scannerFailFast`
   * is true and at least one tool is unavailable. The caller is
   * expected to catch this, log a structured error, and exit 1.
   */
  async discoverTools(): Promise<ResolvedTool[]> {
    const resolved = await this.toolManager.initialise();
    this.tools.splice(0, this.tools.length, ...resolved);

    // Re-wire the adapters with the manager's resolved paths so we
    // never have two competing sources of truth. The `bin` field on
    // each adapter is the only thing the rest of the code reads.
    for (const r of resolved) {
      if (!r.binaryPath) continue;
      switch (r.key) {
        case "semgrep":
          this.scanners.semgrep.setBinaryPath(r.binaryPath);
          break;
        case "gitleaks":
          this.scanners.gitleaks.setBinaryPath(r.binaryPath);
          break;
        case "trivy":
          this.scanners.trivy.setBinaryPath(r.binaryPath);
          break;
      }
    }
    return resolved;
  }

  /** Scanner ids available in this orchestrator. Stable order. */
  scannerIds(): ScannerId[] {
    return ["semgrep", "gitleaks", "trivy"];
  }
}

/**
 * Resolve the orchestrator's `allowedRootSource` from the env, in the
 * documented precedence:
 *
 *   SECURITY_MCP_ALLOWED_ROOT > TARGET_REPO_PATH
 *
 * Returns the first non-empty value, or `null` if neither is set. The
 * caller (`index.ts`) is expected to fall back to walking up to a `.git`
 * entry when this is `null`.
 */
export function resolveAllowedRootSource(env: NodeJS.ProcessEnv): string | null {
  const allowed = (env.SECURITY_MCP_ALLOWED_ROOT ?? "").trim();
  if (allowed) return allowed;
  const target = (env.TARGET_REPO_PATH ?? "").trim();
  if (target) return target;
  return null;
}
