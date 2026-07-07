/**
 * Report engine. Owns the *directory* layout under .security-mcp/reports/ and
 * delegates format-specific work to the json / markdown / sarif modules.
 */
import { join } from "node:path";
import { writeTextFileAtomic, ensureDir } from "../utils/file-utils.js";
import { renderMarkdownReport } from "./markdown-report.js";
import { renderJsonReport } from "./json-report.js";
import { renderSarifReport } from "./sarif-report.js";
import type { SecurityFinding } from "../core/finding.js";

export type ReportFormat = "json" | "markdown" | "sarif";

export interface ReportMeta {
  scanId: string;
  repoRoot: string;
  startedAt: string;
  finishedAt: string;
  scannerVersions: Record<string, string>;
}

export class ReportEngine {
  constructor(private readonly baseDir: string) {}

  async write(
    format: ReportFormat,
    findings: SecurityFinding[],
    meta: ReportMeta
  ): Promise<{ path: string; bytes: number }> {
    await ensureDir(this.baseDir);
    const stamp = new Date(meta.finishedAt).toISOString().replace(/[:.]/g, "-");
    const filename = `${meta.scanId}-${stamp}.${formatExt(format)}`;
    const out = join(this.baseDir, filename);
    const body =
      format === "json"
        ? renderJsonReport(findings, meta)
        : format === "sarif"
        ? renderSarifReport(findings, meta)
        : renderMarkdownReport(findings, meta);
    await writeTextFileAtomic(out, body);
    return { path: out, bytes: Buffer.byteLength(body, "utf8") };
  }
}

function formatExt(f: ReportFormat): string {
  return f === "json" ? "json" : f === "sarif" ? "sarif.json" : "md";
}
