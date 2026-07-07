import type { ToolContext, AnyMcpServer } from "./_shared.js";
import { z, auditWrap, ok } from "./_shared.js";
import { identifyCodebase } from "../stack-detect.js";

export function register(server: AnyMcpServer, ctx: ToolContext): void {
  server.tool(
    "identify_codebase",
    "Detect the technology stack of the current repository. " +
      "Returns a list of matches with confidence scores and evidence.",
    {},
    async (args) =>
      auditWrap(ctx, "identify_codebase", args, async () => {
        const matches = await identifyCodebase(ctx.repoRoot);
        return ok({ matches });
      }),
  );
}
