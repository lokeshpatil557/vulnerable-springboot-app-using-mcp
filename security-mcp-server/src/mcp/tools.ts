/**
 * MCP tool registration. Every public tool is registered exactly once.
 * The actual `register` functions live in `src/tools/*.ts`; this file is
 * a thin re-export that maintains backwards compatibility with the
 * historical `mcp/tools.ts` import path.
 */
import { registerAllTools as registerAllToolsImpl } from "../tools/index.js";

export { registerAllTools } from "../tools/index.js";
