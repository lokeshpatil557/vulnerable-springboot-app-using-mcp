import type { ToolContext, AnyMcpServer } from "./_shared.js";
import { z, auditWrap, ok } from "./_shared.js";
import { runScanners } from "../scanners/registry.js";

export function register(server: AnyMcpServer, ctx: ToolContext): void {
  server.tool(
    "scan_repository",
    "Alias for scan_directory. Run all available scanners against the current Git repository.",
    {
      target: z.string().min(1).max(4096).optional(),
      includeRuleSets: z.array(z.string()).optional(),
      ids: z.array(z.enum(["semgrep", "gitleaks", "trivy"])).optional(),
    },
    async (args) =>
      auditWrap(ctx, "scan_repository", args, async () => {
        const a = args as { target?: string; includeRuleSets?: string[]; ids?: Array<"semgrep" | "gitleaks" | "trivy"> };
        const { findings, unavailable, durationMs, perScanner } = await runScanners(
          {
            root: ctx.repoRoot,
            target: a.target,
            includeRuleSets: a.includeRuleSets ?? ctx.config.includeRuleSets,
            config: ctx.config,
            logger: ctx.logger,
          },
          ctx.scanners,
          { ids: a.ids },
          ctx.logger,
        );
        return ok({ findings, unavailable, durationMs, perScanner });
      }),
  );
}
