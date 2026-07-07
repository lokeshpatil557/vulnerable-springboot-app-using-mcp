import type { ToolContext, AnyMcpServer } from "./_shared.js";
import { z, auditWrap, ok } from "./_shared.js";
import { runScanners } from "../scanners/registry.js";

export function register(server: AnyMcpServer, ctx: ToolContext): void {
  server.tool(
    "run_secret_scan",
    "Run Gitleaks secret detection only.",
    {
      target: z.string().min(1).max(4096).optional(),
    },
    async (args) =>
      auditWrap(ctx, "run_secret_scan", args, async () => {
        const a = args as { target?: string };
        const { findings, unavailable, durationMs, perScanner } = await runScanners(
          {
            root: ctx.repoRoot,
            target: a.target,
            config: ctx.config,
            logger: ctx.logger,
          },
          ctx.scanners,
          { ids: ["gitleaks"] },
          ctx.logger,
        );
        return ok({ findings, unavailable, durationMs, perScanner });
      }),
  );
}
