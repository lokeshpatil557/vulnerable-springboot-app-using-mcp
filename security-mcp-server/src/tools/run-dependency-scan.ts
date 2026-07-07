import type { ToolContext, AnyMcpServer } from "./_shared.js";
import { auditWrap, ok } from "./_shared.js";
import { runScanners } from "../scanners/registry.js";

export function register(server: AnyMcpServer, ctx: ToolContext): void {
  server.tool(
    "run_dependency_scan",
    "Run Trivy filesystem scan (CVE in OS packages and language dependencies).",
    {},
    async (args) =>
      auditWrap(ctx, "run_dependency_scan", args, async () => {
        const { findings, unavailable, durationMs, perScanner } = await runScanners(
          {
            root: ctx.repoRoot,
            config: ctx.config,
            logger: ctx.logger,
          },
          ctx.scanners,
          { ids: ["trivy"], trivyMode: "fs" },
          ctx.logger,
        );
        return ok({ findings, unavailable, durationMs, perScanner });
      }),
  );
}
