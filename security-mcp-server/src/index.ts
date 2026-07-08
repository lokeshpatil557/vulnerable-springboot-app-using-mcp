import { parseArgs } from "node:util";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { loadConfig } from "./config.js";
import { createLogger } from "./logger.js";
import { createAuditLogger } from "./audit.js";
import { resolveRepoRoot } from "./paths.js";
import {
  resolveAllowedRootSource,
  SecurityOrchestrator,
} from "./orchestrator.js";
import { createServer } from "./server.js";
import { ScannerDependencyMissingError } from "./errors.js";

const HELP = `security-mcp-server — MCP server for security scanning, stack detection, and verified remediation

Usage:
  security-mcp-server [--repo-root <path>] [--print-config] [--version] [--help]

Options:
  --repo-root <path>  Override the resolved Git repository root
  --print-config      Print the resolved configuration as JSON and exit
  -v, --version       Print version and exit
  -h, --help          Show this help text and exit

Environment:
  SECURITY_MCP_ALLOWED_ROOT  Highest-precedence repo-root override.
  TARGET_REPO_PATH           Fallback repo-root (used when
                             SECURITY_MCP_ALLOWED_ROOT is unset).
  LOG_LEVEL, AUDIT_LOG_PATH, SCAN_TIMEOUT_MS,
  MAX_CONCURRENT_SCANNERS, SEMGREP_PATH, GITLEAKS_PATH, TRIVY_PATH,
  INCLUDE_RULE_SETS, REDACT_IN_REPORTS, SCANNER_FAIL_FAST
                             SCANNER_FAIL_FAST=1 makes the server exit
                             at boot if any of semgrep / gitleaks /
                             trivy cannot be located on PATH (or via
                             the *_PATH env vars). Default: off.

The server speaks the MCP protocol over stdio. All logging is written to
stderr so the protocol stream on stdout stays clean.
`;

async function main(): Promise<void> {
  let parsed;
  try {
    parsed = parseArgs({
      options: {
        "repo-root": { type: "string" },
        "print-config": { type: "boolean", default: false },
        version: { type: "boolean", short: "v", default: false },
        help: { type: "boolean", short: "h", default: false },
      },
      allowPositionals: false,
      strict: true,
    });
  } catch (err) {
    process.stderr.write(`security-mcp-server: ${(err as Error).message}\n`);
    process.stderr.write(HELP);
    process.exit(64);
  }

  if (parsed.values.help) {
    process.stdout.write(HELP);
    process.exit(0);
  }
  if (parsed.values.version) {
    process.stdout.write("security-mcp-server 0.1.0\n");
    process.exit(0);
  }

  const config = loadConfig(process.env, {
    repoRoot: typeof parsed.values["repo-root"] === "string" ? parsed.values["repo-root"] : undefined,
  });

  if (parsed.values["print-config"]) {
    process.stdout.write(JSON.stringify(config, null, 2) + "\n");
    process.exit(0);
  }

  const logger = createLogger(config);
  const repoRoot =
    config.repoRoot === "auto"
      ? resolveRepoRoot(process.cwd())
      : resolveRepoRoot(config.repoRoot);
  const audit = await createAuditLogger(config, repoRoot);
  const allowedRootSource = resolveAllowedRootSource(process.env);

  // Compose the orchestrator: scanner registry + plugin registry + remediation.
  const orchestrator = new SecurityOrchestrator({
    config,
    logger,
    repoRoot,
    allowedRootSource,
  });

  // Discover external scanners (semgrep / gitleaks / trivy) before we
  // bind stdio. When SCANNER_FAIL_FAST=1, this throws
  // `ScannerDependencyMissingError` on the first missing scanner and
  // we exit 1 with a structured error on stderr — no half-initialised
  // MCP server is ever left around.
  let resolvedTools;
  try {
    resolvedTools = await orchestrator.discoverTools();
    if (config.scannerFailFast) {
      const missing = resolvedTools.filter((r) => !r.available);
      if (missing.length > 0) {
        // Will be caught by the main().catch below.
        throw new ScannerDependencyMissingError(
          missing.map((m) => ({
            key: m.key,
            reason: m.reason,
            binaryPath: m.binaryPath,
            status: m.status,
          })),
        );
      }
    }
  } catch (err) {
    if (err instanceof ScannerDependencyMissingError) {
      // Print to stderr directly — never via the logger's destination
      // abstraction, so the message reaches the operator even if the
      // logger was reconfigured by a test harness.
      process.stderr.write(
        `security-mcp-server: required scanner(s) unavailable\n` +
          err.message +
          "\n" +
          "Set SCANNER_FAIL_FAST=0 (or unset it) to start the server " +
          "anyway; missing scanners will be reported per-tool via the " +
          "`unavailable[]` array.\n",
      );
    }
    throw err;
  }

  logger.info(
    { repoRoot, auditPath: audit.path },
    "security-mcp-server starting",
  );

  const server = createServer({
    config,
    logger,
    audit,
    orchestrator,
    repoRoot,
    scanners: orchestrator.scanners,
  });
  const transport = new StdioServerTransport();
  await server.connect(transport);

  // Graceful shutdown.
  const shutdown = async (signal: string) => {
    logger.info({ signal }, "shutting down");
    try {
      await server.close();
    } catch (err) {
      logger.warn({ err: String(err) }, "error during server.close()");
    }
    try {
      await audit.flush();
    } catch (err) {
      logger.warn({ err: String(err) }, "error during audit.flush()");
    }
    process.exit(0);
  };
  process.on("SIGTERM", () => void shutdown("SIGTERM"));
  process.on("SIGINT", () => void shutdown("SIGINT"));
  process.on("uncaughtException", (err) => {
    logger.error({ err: String(err) }, "uncaughtException");
    void shutdown("uncaughtException").then(() => process.exit(1));
  });
  process.on("unhandledRejection", (reason) => {
    logger.error({ reason: String(reason) }, "unhandledRejection");
  });
}

main().catch((err) => {
  process.stderr.write(`security-mcp-server: fatal: ${(err as Error).stack ?? err}\n`);
  process.exit(1);
});
