import { join, isAbsolute } from "node:path";
import type { ToolContext, AnyMcpServer } from "./_shared.js";
import { z, auditWrap, ok } from "./_shared.js";
import { runScanners } from "../scanners/registry.js";

export function register(server: AnyMcpServer, ctx: ToolContext): void {
  server.tool(
    "generate_sbom",
    "Generate a CycloneDX SBOM via Trivy. The output is written under `.security-mcp/sbom/` " +
      "unless `destPath` is supplied (relative to repo root or absolute).",
    {
      destPath: z.string().optional(),
    },
    async (args) =>
      auditWrap(ctx, "generate_sbom", args, async () => {
        const a = args as { destPath?: string };
        const dest = a.destPath
          ? (isAbsolute(a.destPath) ? a.destPath : join(ctx.repoRoot, a.destPath))
          : join(ctx.repoRoot, ".security-mcp", "sbom", "trivy.cdx.json");
        const { unavailable, durationMs } = await runScanners(
          { root: ctx.repoRoot, config: ctx.config, logger: ctx.logger },
          ctx.scanners,
          { ids: ["trivy"], trivyMode: "sbom", trivySbomOutPath: dest },
          ctx.logger,
        );
        return ok({ sbomPath: dest, unavailable, durationMs });
      }),
  );
}
