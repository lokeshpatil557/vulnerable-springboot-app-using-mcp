import { join } from "node:path";
import type { ToolContext, AnyMcpServer, RunScannersInput } from "./_shared.js";
import { RunScannersInput as RunScannersSchema, auditWrap, ok } from "./_shared.js";
import { runScanners } from "../scanners/registry.js";
import { readTextFile } from "../util/fs.js";

export function register(server: AnyMcpServer, ctx: ToolContext): void {
  server.tool(
    "scan_directory",
    "Run all available scanners against the current Git repository. " +
      "Returns normalized findings plus a list of any scanners that were unavailable on this host.",
    RunScannersSchema.shape,
    async (args) =>
      auditWrap(ctx, "scan_directory", args, async () => {
        const input = args as unknown as RunScannersInput;
        const { findings, unavailable, durationMs, perScanner } = await runScanners(
          {
            root: ctx.repoRoot,
            target: input.target,
            includeRuleSets: input.includeRuleSets ?? ctx.config.includeRuleSets,
            config: ctx.config,
            logger: ctx.logger,
          },
          ctx.scanners,
          { ids: input.ids },
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
        return ok({
          scanId,
          findings,
          unavailable,
          durationMs,
          perScanner,
          scanPath: rel(ctx.repoRoot, scanPath),
        });
      }),
  );
}

function rel(_repoRoot: string, _p: string): string {
  return _p;
}
