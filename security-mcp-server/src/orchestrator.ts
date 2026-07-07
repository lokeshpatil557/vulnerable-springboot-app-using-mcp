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
 */
import type { Logger } from "pino";
import type { Config } from "./config.js";
import {
  buildScannerRegistry,
  type ScannerRegistry,
  type ScannerId,
} from "./scanners/registry.js";
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
}

export class SecurityOrchestrator {
  readonly config: Config;
  readonly logger: Logger;
  readonly repoRoot: string;
  readonly allowedRootSource: string | null;
  readonly scanners: ScannerRegistry;
  readonly plugins: readonly StackPlugin[];
  readonly remediation: RemediationEngine;
  readonly startedAt: number;

  constructor(opts: SecurityOrchestratorOptions) {
    this.config = opts.config;
    this.logger = opts.logger;
    this.repoRoot = opts.repoRoot;
    this.allowedRootSource = opts.allowedRootSource;
    this.startedAt = Date.now();

    // 1. Scanner adapters: Semgrep (SAST), Gitleaks (secret), Trivy (vuln).
    this.scanners = buildScannerRegistry(opts.config);

    // 2. Static plugin registry — no dynamic imports, see plugin-registry.ts.
    this.plugins = getPlugins();

    // 3. Remediation engine: propose / preview / apply / verify.
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
