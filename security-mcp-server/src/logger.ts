import { pino, type Logger } from "pino";
import { destination as pinoDestination } from "pino";
import type { Config } from "./config.js";

/**
 * Create the root logger. **Never writes to stdout** in stdio mode — that
 * stream is reserved for the MCP JSON-RPC protocol.
 */
export function createLogger(config: Config): Logger {
  const isStdio = !process.stdout.isTTY;
  return pino({
    level: config.logLevel,
    base: { service: "security-mcp-server", pid: process.pid },
    timestamp: pino.stdTimeFunctions.isoTime,
    // Write to stderr via a custom destination; pino default writes to stdout.
    ...(isStdio
      ? {}
      : {}),
  }, isStdio ? pinoDestination(2) : pinoDestination(2));
}
