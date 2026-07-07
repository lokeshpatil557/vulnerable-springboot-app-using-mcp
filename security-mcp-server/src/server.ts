import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { Config } from "./config.js";
import type { Logger } from "pino";
import type { AuditLogger } from "./audit.js";
import type { ScannerRegistry } from "./scanners/registry.js";
import { registerAllTools, type ToolContext } from "./tools/index.js";

export interface ServerDeps {
  config: Config;
  logger: Logger;
  audit: AuditLogger;
  scanners: ScannerRegistry;
  repoRoot: string;
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
    repoRoot: deps.repoRoot,
    config: deps.config,
    logger: deps.logger,
    audit: deps.audit,
    scanners: deps.scanners,
    startedAt: Date.now(),
  };

  registerAllTools(server, ctx);
  return server;
}
