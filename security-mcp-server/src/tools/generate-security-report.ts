import { readFile } from "node:fs/promises";
import { join, isAbsolute } from "node:path";
import type { ToolContext, AnyMcpServer } from "./_shared.js";
import { z, auditWrap, ok } from "./_shared.js";
import { writeJsonReport } from "../reports/json.js";
import { writeMarkdownReport } from "../reports/markdown.js";
import type { SecurityFinding } from "../findings.js";

interface StoredScan {
  schemaVersion: string;
  meta: {
    repoRoot: string;
    scannerVersions: Record<string, string | undefined>;
    scanId: string;
    startedAt: string;
    finishedAt: string;
    durationMs: number;
  };
  findings: SecurityFinding[];
}

export function register(server: AnyMcpServer, ctx: ToolContext): void {
  server.tool(
    "generate_security_report",
    "Write JSON + Markdown reports for a prior scan. The scan must be persisted under `.security-mcp/scans/`.",
    {
      scanId: z.string().min(1).max(256),
      destDir: z.string().optional(),
    },
    async (args) =>
      auditWrap(ctx, "generate_security_report", args, async () => {
        const a = args as { scanId: string; destDir?: string };
        const scanPath = join(ctx.repoRoot, ".security-mcp", "scans", `${a.scanId}.json`);
        let stored: StoredScan;
        try {
          stored = JSON.parse(await readFile(scanPath, "utf8"));
        } catch {
          throw new Error(`scan not found: ${a.scanId}`);
        }
        const destDir = a.destDir
          ? (isAbsolute(a.destDir) ? a.destDir : join(ctx.repoRoot, a.destDir))
          : join(ctx.repoRoot, ".security-mcp", "reports");
        const jsonPath = await writeJsonReport(stored.findings, join(destDir, `${a.scanId}.json`), stored.meta);
        const mdPath = await writeMarkdownReport(stored.findings, join(destDir, `${a.scanId}.md`), stored.meta);
        return ok({ jsonPath, markdownPath: mdPath });
      }),
  );
}
