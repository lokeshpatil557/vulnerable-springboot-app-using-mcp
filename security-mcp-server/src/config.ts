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
  pathSafety: z
    .object({
      /**
       * SECURITY_MCP_ALLOWED_ROOT (highest priority) overrides everything.
       * Empty by default; populated by env precedence in applyEnvPathSafety.
       */
      allowedRoot: z.string().default(""),
      /** Max size of any single file the server will read. Default 25 MiB. */
      maxFileBytes: z.number().int().positive().default(26_214_400),
      /** Max total size of the repo tree the server will scan. Default 1 GiB. */
      maxRepoBytes: z.number().int().positive().default(1_073_741_824),
      /** Max size of an inbound `diff` payload. Default 1 MiB. */
      maxDiffBytes: z.number().int().positive().default(1_048_576),
      /** When true, follow symlinks (target must still be inside the repo). Default false. */
      followSymlinks: z.boolean().default(false),
      /** When true, the apply_remediation tool is enabled. Default false (fail-closed). */
      allowApplyRemediation: z.boolean().default(false),
      /**
       * Regex strings matched against the relative path of any inbound file
       * arg. Secret-bearing dotfiles and SSH/AWS credential files are
       * blocked by default.
       */
      blockedFiles: z
        .array(z.string())
        .default([
          "\\.env(\\..*)?$",
          "^id_rsa(\\.pub)?$",
          "^id_ed25519(\\.pub)?$",
          "(^|/)\\.ssh/.*",
          "(^|/)\\.aws/credentials$",
          "(^|/)\\.npmrc$",
          "(^|/)\\.pypirc$",
          "(^|/)\\.netrc$",
          "(^|/)\\.gitconfig$",
          "(^|/)\\.pgpass$",
        ]),
      /**
       * Populated at boot from os.homedir() / platform root. Users can
       * extend this list via the BLOCKED_ANCESTORS env var (csv).
       */
      forbiddenAncestors: z.array(z.string()).default([]),
    })
    .default({}),
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
  // Path-safety keys
  SECURITY_MCP_ALLOWED_ROOT: "pathSafety.allowedRoot",
  MAX_FILE_BYTES: "pathSafety.maxFileBytes",
  MAX_REPO_BYTES: "pathSafety.maxRepoBytes",
  MAX_DIFF_BYTES: "pathSafety.maxDiffBytes",
  FOLLOW_SYMLINKS: "pathSafety.followSymlinks",
  ALLOW_APPLY_REMEDIATION: "pathSafety.allowApplyRemediation",
  BLOCKED_FILES: "pathSafety.blockedFiles",
  BLOCKED_ANCESTORS: "pathSafety.forbiddenAncestors",
};

/**
 * Apply the documented repo-root precedence:
 *   SECURITY_MCP_ALLOWED_ROOT > TARGET_REPO_PATH
 *
 * Empty / unset values are ignored. If neither is set, the input is
 * returned unchanged (caller falls through to the schema default `"auto"`).
 *
 * SECURITY_MCP_ALLOWED_ROOT is ALSO stamped onto `pathSafety.allowedRoot`
 * so the path-safety module has a single source of truth.
 */
function applyEnvRepoRoot(env: NodeJS.ProcessEnv, input: Record<string, unknown>): void {
  const allowed = (env.SECURITY_MCP_ALLOWED_ROOT ?? "").trim();
  if (allowed) {
    input.repoRoot = allowed;
    const ps =
      (input.pathSafety as Record<string, unknown> | undefined) ?? {};
    ps.allowedRoot = allowed;
    input.pathSafety = ps;
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
    if (
      schemaKey === "scanTimeoutMs" ||
      schemaKey === "maxConcurrentScanners" ||
      schemaKey === "pathSafety.maxFileBytes" ||
      schemaKey === "pathSafety.maxRepoBytes" ||
      schemaKey === "pathSafety.maxDiffBytes"
    ) {
      const n = Number(raw);
      if (Number.isFinite(n)) {
        if (schemaKey.startsWith("pathSafety.")) {
          const ps = (out.pathSafety as Record<string, unknown> | undefined) ?? {};
          ps[schemaKey.slice("pathSafety.".length)] = n;
          out.pathSafety = ps;
        } else {
          out[schemaKey] = n;
        }
      }
    } else if (schemaKey === "includeRuleSets") {
      out[schemaKey] = raw.split(",").map((s) => s.trim()).filter(Boolean);
    } else if (
      schemaKey === "redactInReports" ||
      schemaKey === "pathSafety.followSymlinks" ||
      schemaKey === "pathSafety.allowApplyRemediation"
    ) {
      const v = raw === "1" || raw.toLowerCase() === "true";
      if (schemaKey.startsWith("pathSafety.")) {
        const ps = (out.pathSafety as Record<string, unknown> | undefined) ?? {};
        ps[schemaKey.slice("pathSafety.".length)] = v;
        out.pathSafety = ps;
      } else {
        out[schemaKey] = v;
      }
    } else if (
      schemaKey === "pathSafety.blockedFiles" ||
      schemaKey === "pathSafety.forbiddenAncestors"
    ) {
      const arr = raw.split(",").map((s) => s.trim()).filter(Boolean);
      const ps = (out.pathSafety as Record<string, unknown> | undefined) ?? {};
      ps[schemaKey.slice("pathSafety.".length)] = arr;
      out.pathSafety = ps;
    } else if (schemaKey === "pathSafety.allowedRoot") {
      const ps = (out.pathSafety as Record<string, unknown> | undefined) ?? {};
      ps.allowedRoot = raw;
      out.pathSafety = ps;
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
