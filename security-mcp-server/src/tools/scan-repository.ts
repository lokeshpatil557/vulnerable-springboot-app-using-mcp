 import { join } from "node:path";
import type { ToolContext, AnyMcpServer } from "./_shared.js";
import { z, auditWrap, ok } from "./_shared.js";
import { runScanners } from "../scanners/registry.js";

export function register(server: AnyMcpServer, ctx: ToolContext): void {
  server.tool(
    "scan_repository",
    "Alias for scan_directory. Run all available scanners against the current Git repository and persist results for downstream tools.",
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
        // Persist findings for downstream tools (verify_fix, generate_security_report).
        const scanId = `scan-${Date.now()}`;
        const scanPath = join(ctx.repoRoot, ".security-mcp", "scans", `${scanId}.json`);
        const { writeJsonReport } = await import("../reports/json.js");
        await writeJsonReport(findings, scanPath, {
          repoRoot: ctx.repoRoot,
          scannerVersions: {
            semgrep: undefined,
            gitleaks: undefined,
            trivy: undefined,
          },
          scanId,
          startedAt: new Date().toISOString(),
          finishedAt: new Date().toISOString(),
          durationMs,
        });
        return ok({ scanId, findings, unavailable, durationMs, perScanner, scanPath });
      }),
  );
}
