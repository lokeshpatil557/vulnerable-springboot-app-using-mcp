/**
 * `generate_security_report` — produces JSON, Markdown, and SARIF
 * reports for a prior persisted scan.
 *
 *   formats: ["json" | "markdown" | "sarif"] (default: all three)
 *   destDir: output directory (default: .security-mcp/reports/)
 *
 * Returns the absolute paths of the written files.
 */
import { readFile } from "node:fs/promises";
import { join, isAbsolute } from "node:path";
import type { ToolContext, AnyMcpServer } from "./_shared.js";
import { z, auditWrap, ok } from "./_shared.js";
import { writeJsonReport } from "../reports/json.js";
import { writeMarkdownReport } from "../reports/markdown.js";
import { writeSarifReport } from "../reports/sarif.js";
import type { SecurityFinding } from "../findings.js";

export type ReportFormat = "json" | "markdown" | "sarif";

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
    "Write JSON, Markdown, and SARIF reports for a prior persisted scan. " +
      "The scan must be persisted under `.security-mcp/scans/`. " +
      "Use the `formats` array to select which to write; defaults to all three.",
    {
      scanId: z.string().min(1).max(256),
      destDir: z.string().optional(),
      formats: z
        .array(z.enum(["json", "markdown", "sarif"]))
        .optional()
        .default(["json", "markdown", "sarif"]),
    },
    async (args) =>
      auditWrap(ctx, "generate_security_report", args, async () => {
        const a = args as {
          scanId: string;
          destDir?: string;
          formats?: ReportFormat[];
        };
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

        const formats: ReportFormat[] =
          a.formats && a.formats.length > 0
            ? a.formats
            : ["json", "markdown", "sarif"];

        const out: Record<string, string> = {};
        if (formats.includes("json")) {
          out.jsonPath = await writeJsonReport(
            stored.findings,
            join(destDir, `${a.scanId}.json`),
            stored.meta,
          );
        }
        if (formats.includes("markdown")) {
          out.markdownPath = await writeMarkdownReport(
            stored.findings,
            join(destDir, `${a.scanId}.md`),
            stored.meta,
          );
        }
        if (formats.includes("sarif")) {
          out.sarifPath = await writeSarifReport(
            stored.findings,
            join(destDir, `${a.scanId}.sarif.json`),
            stored.meta,
          );
        }
        return ok({ scanId: a.scanId, destDir, ...out });
      }),
  );
}
