import type { Logger } from "pino";
import type { Config } from "../config.js";
import type { ScannerId } from "./finding.js";
import { resolveRepoRoot } from "../security/path-safety.js";

/**
 * Context passed to every scanner invocation. Built once per request and
 * frozen — scanners must not mutate it.
 */
export interface ScanContext {
  /** Absolute path to the Git repository root. */
  readonly repoRoot: string;
  /** Optional file/dir target inside the repo. */
  readonly target?: string;
  /** Semgrep rule packs to include. */
  readonly includeRuleSets: readonly string[];
  /** Optional extra Semgrep YAML rule fragments. */
  readonly extraRules: readonly string[];
  /** Active scanner ids (restricts which adapters run). */
  readonly scannerIds: readonly ScannerId[];
  /** Resolved configuration. */
  readonly config: Config;
  /** Pino-shaped logger. */
  readonly logger: Logger;
  /** Unique scan id for correlation. */
  readonly scanId: string;
  /** Caller-supplied request id. */
  readonly requestId: string;
  /** Wall-clock start (ms). */
  readonly startedAt: number;
}

/** Resolved, immutable configuration (re-exported from config module). */
export type { Config } from "../config.js";

const DEFAULTS: Config = {
  repoRoot: "auto",
  logLevel: "info",
  auditLogPath: ".security-mcp/audit.jsonl",
  scanTimeoutMs: 300_000,
  maxConcurrentScanners: 2,
  perScannerBinaries: {},
  includeRuleSets: [],
  redactInReports: true,
  scannerFailFast: false,
  pathSafety: {
    allowedRoot: "",
    maxFileBytes: 26_214_400,
    maxRepoBytes: 1_073_741_824,
    maxDiffBytes: 1_048_576,
    followSymlinks: false,
    allowApplyRemediation: false,
    blockedFiles: [],
    forbiddenAncestors: [],
  },
};

/**
 * Build a `ScanContext` from raw inputs. Resolves the repo root, normalizes
 * scanner IDs, and freezes the context so downstream code cannot mutate it.
 */
export function buildScanContext(input: {
  repoRoot?: string;
  target?: string;
  includeRuleSets?: string[];
  extraRules?: string[];
  scannerIds?: ScannerId[];
  config?: Partial<Config>;
  logger: Logger;
  scanId: string;
  requestId: string;
}): ScanContext {
  const cfg: Config = { ...DEFAULTS, ...(input.config ?? {}) };
  const repoRoot = cfg.repoRoot === "auto" || !cfg.repoRoot ? resolveRepoRoot(process.cwd()) : cfg.repoRoot;
  return Object.freeze({
    repoRoot,
    target: input.target,
    includeRuleSets: Object.freeze([...(input.includeRuleSets ?? cfg.includeRuleSets)]),
    extraRules: Object.freeze([...(input.extraRules ?? [])]),
    scannerIds: Object.freeze([...(input.scannerIds ?? [])]),
    config: cfg,
    logger: input.logger,
    scanId: input.scanId,
    requestId: input.requestId,
    startedAt: Date.now(),
  });
}
