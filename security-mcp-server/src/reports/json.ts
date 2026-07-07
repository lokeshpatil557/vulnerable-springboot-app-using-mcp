import { mkdir, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, join } from "node:path";
import { groupBySeverity, topRules } from "../compliance.js";
import type { SecurityFinding } from "../findings.js";

export interface ReportMeta {
  repoRoot: string;
  scannerVersions: Record<string, string | undefined>;
  scanId: string;
  startedAt: string;
  finishedAt: string;
  durationMs: number;
}

export interface JsonReport {
  schemaVersion: "1.0.0";
  meta: ReportMeta;
  summary: {
    total: number;
    bySeverity: Record<string, number>;
    topRules: { ruleId: string; count: number }[];
  };
  findings: SecurityFinding[];
}

export async function writeJsonReport(
  findings: SecurityFinding[],
  destPath: string,
  meta: ReportMeta,
): Promise<string> {
  const report: JsonReport = {
    schemaVersion: "1.0.0",
    meta,
    summary: {
      total: findings.length,
      bySeverity: groupBySeverity(findings),
      topRules: topRules(findings, 10),
    },
    findings,
  };
  const abs = isAbsolute(destPath) ? destPath : join(meta.repoRoot, destPath);
  await mkdir(dirname(abs), { recursive: true });
  await writeFile(abs, JSON.stringify(report, null, 2), "utf8");
  return abs;
}
