import { z } from "zod";

const LogLevelSchema = z.enum(["trace", "debug", "info", "warn", "error", "fatal"]);

const ConfigSchema = z.object({
  repoRoot: z.string().default("auto"),
  logLevel: LogLevelSchema.default("info"),
  auditLogPath: z.string().default(".security-mcp/audit.jsonl"),
  scanTimeoutMs: z.number().int().positive().default(300_000),
  maxConcurrentScanners: z.number().int().positive().max(8).default(2),
  perScannerBinaries: z
    .object({
      semgrep: z.string().optional(),
      gitleaks: z.string().optional(),
      trivy: z.string().optional(),
    })
    .default({}),
  includeRuleSets: z.array(z.string()).default([]),
  redactInReports: z.boolean().default(true),
});

export type Config = z.infer<typeof ConfigSchema>;

/**
 * Env-var → config-field map. The two repo-root vars follow the contract
 * documented in the bootstrap:
 *
 *   SECURITY_MCP_ALLOWED_ROOT > TARGET_REPO_PATH
 *
 * Both are merged onto `repoRoot` via `applyEnvRepoRoot()` so the existing
 * schema default / CLI override path is preserved.
 */
const ENV_KEY_MAP: Record<string, string> = {
  LOG_LEVEL: "logLevel",
  AUDIT_LOG_PATH: "auditLogPath",
  SCAN_TIMEOUT_MS: "scanTimeoutMs",
  MAX_CONCURRENT_SCANNERS: "maxConcurrentScanners",
  SEMGREP_PATH: "perScannerBinaries.semgrep",
  GITLEAKS_PATH: "perScannerBinaries.gitleaks",
  TRIVY_PATH: "perScannerBinaries.trivy",
  INCLUDE_RULE_SETS: "includeRuleSets",
  REDACT_IN_REPORTS: "redactInReports",
};

/**
 * Apply the documented repo-root precedence:
 *   SECURITY_MCP_ALLOWED_ROOT > TARGET_REPO_PATH
 *
 * Empty / unset values are ignored. If neither is set, the input is
 * returned unchanged (caller falls through to the schema default `"auto"`).
 */
function applyEnvRepoRoot(env: NodeJS.ProcessEnv, input: Record<string, unknown>): void {
  const allowed = (env.SECURITY_MCP_ALLOWED_ROOT ?? "").trim();
  if (allowed) {
    input.repoRoot = allowed;
    return;
  }
  const target = (env.TARGET_REPO_PATH ?? "").trim();
  if (target) {
    input.repoRoot = target;
  }
}

function envToInput(env: NodeJS.ProcessEnv): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [envKey, schemaKey] of Object.entries(ENV_KEY_MAP)) {
    const raw = env[envKey];
    if (raw === undefined || raw === "") continue;
    if (schemaKey === "scanTimeoutMs" || schemaKey === "maxConcurrentScanners") {
      const n = Number(raw);
      if (Number.isFinite(n)) out[schemaKey] = n;
    } else if (schemaKey === "includeRuleSets") {
      out[schemaKey] = raw.split(",").map((s) => s.trim()).filter(Boolean);
    } else if (schemaKey === "redactInReports") {
      out[schemaKey] = raw === "1" || raw.toLowerCase() === "true";
    } else if (schemaKey.startsWith("perScannerBinaries.")) {
      const inner = (out.perScannerBinaries as Record<string, string> | undefined) ?? {};
      inner[schemaKey.split(".")[1]!] = raw;
      out.perScannerBinaries = inner;
    } else {
      out[schemaKey] = raw;
    }
  }
  applyEnvRepoRoot(env, out);
  return out;
}

/** Load and validate configuration from environment variables and optional CLI overrides. */
export function loadConfig(
  env: NodeJS.ProcessEnv,
  overrides: Partial<Config> = {},
): Config {
  const merged: Record<string, unknown> = { ...envToInput(env), ...overrides };
  return ConfigSchema.parse(merged);
}

/** Defaults for documentation / `--print-config`. */
export function defaultConfig(): Config {
  return ConfigSchema.parse({});
}
