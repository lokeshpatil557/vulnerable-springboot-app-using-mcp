import type { ToolContext, AnyMcpServer } from "./_shared.js";
import { auditWrap, ok } from "./_shared.js";
import { getAdapters } from "../adapters/registry.js";

export function register(server: AnyMcpServer, _ctx: ToolContext): void {
  server.tool(
    "_supported_stacks",
    "List the technology stacks the server knows how to detect. Static — independent of the host environment.",
    {},
    async (args) =>
      auditWrap(_ctx, "_supported_stacks", args, async () => {
        const stacks = getAdapters().map((a) => ({ id: a.id, displayName: a.displayName }));
        return ok({ stacks });
      }),
  );
}
