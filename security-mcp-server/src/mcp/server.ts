/**
 * MCP server bootstrap. Wires the ScanContext, audit logger, and tool
 * registry into a McpServer instance and connects it over stdio.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import type { ScanContext } from "../core/scan-context.js";
import { registerAllTools } from "./tools.js";

export async function startServer(ctx: ScanContext): Promise<void> {
  const server = new McpServer(
    {
      name: "security-mcp-server",
      version: "0.1.0",
    },
    {
      capabilities: {
        tools: {},
      },
    }
  );

  registerAllTools(server, ctx);

  const transport = new StdioServerTransport();
  await server.connect(transport);
  // Logging intentionally omitted on connect — anything written to stdout
  // would corrupt the JSON-RPC stream. Use ctx.logger (stderr) for diagnostics.
}

export function createMcpServer(ctx: ScanContext): McpServer {
  const server = new McpServer(
    {
      name: "security-mcp-server",
      version: "0.1.0",
    },
    {
      capabilities: { tools: {} },
    }
  );
  registerAllTools(server, ctx);
  return server;
}
