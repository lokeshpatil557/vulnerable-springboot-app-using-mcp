import type { ToolContext, AnyMcpServer } from "./_shared.js";
import { z, auditWrap, ok } from "./_shared.js";
import { runScanners } from "../scanners/registry.js";

export function register(server: AnyMcpServer, ctx: ToolContext): void {
  server.tool(
    "run_sast",
    "Run Semgrep SAST only. Returns a SARIF-shaped findings list.",
    {
      target: z.string().min(1).max(4096).optional(),
      includeRuleSets: z.array(z.string()).optional(),
    },
    async (args) =>
      auditWrap(ctx, "run_sast", args, async () => {
        const a = args as { target?: string; includeRuleSets?: string[] };
        const { findings, unavailable, durationMs, perScanner } = await runScanners(
          {
            root: ctx.repoRoot,
            target: a.target,
            includeRuleSets: a.includeRuleSets ?? ctx.config.includeRuleSets,
            config: ctx.config,
            logger: ctx.logger,
          },
          ctx.scanners,
          { ids: ["semgrep"] },
          ctx.logger,
        );
        return ok({ findings, unavailable, durationMs, perScanner });
      }),
  );
}
