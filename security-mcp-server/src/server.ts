import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { Config } from "./config.js";
import type { Logger } from "pino";
import type { AuditLogger } from "./audit.js";
import type { SecurityOrchestrator } from "./orchestrator.js";
import { registerAllTools, type ToolContext } from "./tools/index.js";

export interface ServerDeps {
  config: Config;
  logger: Logger;
  audit: AuditLogger;
  orchestrator: SecurityOrchestrator;
  /** @deprecated prefer `orchestrator.repoRoot`; kept for tool back-compat. */
  repoRoot: string;
  /** @deprecated prefer `orchestrator.scanners`; kept for tool back-compat. */
  scanners: SecurityOrchestrator["scanners"];
}

/** Build an MCP server instance with every tool registered. */
export function createServer(deps: ServerDeps): McpServer {
  const server = new McpServer(
    {
      name: "security-mcp-server",
      version: "0.1.0",
    },
    {
      capabilities: {
        tools: {},
      },
    },
  );

  const ctx: ToolContext = {
    repoRoot: deps.orchestrator.repoRoot,
    config: deps.config,
    logger: deps.logger,
    audit: deps.audit,
    scanners: deps.orchestrator.scanners,
    orchestrator: deps.orchestrator,
    startedAt: deps.orchestrator.startedAt,
  };

  registerAllTools(server, ctx);
  return server;
}
