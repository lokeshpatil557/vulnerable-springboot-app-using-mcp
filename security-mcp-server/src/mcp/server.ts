/**
 * MCP server bootstrap. Wires the ToolContext, audit logger, and tool
 * registry into a McpServer instance and connects it over stdio.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { registerAllTools, type ToolContext } from "../tools/index.js";

export async function startServer(ctx: ToolContext): Promise<void> {
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

export function createMcpServer(ctx: ToolContext): McpServer {
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
