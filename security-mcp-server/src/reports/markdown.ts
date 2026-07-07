import { mkdir, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, join } from "node:path";
import { groupByCwe, groupByOwasp, groupBySeverity, topRules } from "../compliance.js";
import type { SecurityFinding, Severity } from "../findings.js";
import type { ReportMeta } from "./json.js";

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export async function writeMarkdownReport(
  findings: SecurityFinding[],
  destPath: string,
  meta: ReportMeta,
): Promise<string> {
  const md = renderMarkdown(findings, meta);
  const abs = isAbsolute(destPath) ? destPath : join(meta.repoRoot, destPath);
  await mkdir(dirname(abs), { recursive: true });
  await writeFile(abs, md, "utf8");
  return abs;
}

export function renderMarkdown(findings: SecurityFinding[], meta: ReportMeta): string {
  const lines: string[] = [];
  lines.push(`# Security report — ${meta.scanId}`);
  lines.push("");
  lines.push(`- Repository: \`${meta.repoRoot}\``);
  lines.push(`- Started: ${meta.startedAt}`);
  lines.push(`- Finished: ${meta.finishedAt}`);
  lines.push(`- Duration: ${meta.durationMs}ms`);
  lines.push(
    `- Scanners: ${Object.entries(meta.scannerVersions)
      .map(([k, v]) => `${k}@${v ?? "?"}`)
      .join(", ")}`,
  );
  lines.push("");

  lines.push("## Summary");
  lines.push("");
  const bySev = groupBySeverity(findings);
  lines.push("| Severity | Count |");
  lines.push("|---|---:|");
  for (const s of SEVERITY_ORDER) {
    lines.push(`| ${s} | ${bySev[s] ?? 0} |`);
  }
  lines.push(`| **Total** | **${findings.length}** |`);
  lines.push("");

  const top = topRules(findings, 10);
  if (top.length > 0) {
    lines.push("### Top rules");
    lines.push("");
    lines.push("| Rule | Hits |");
    lines.push("|---|---:|");
    for (const r of top) lines.push(`| \`${r.ruleId}\` | ${r.count} |`);
    lines.push("");
  }

  const byOwasp = groupByOwasp(findings);
  if (Object.keys(byOwasp).length > 0) {
    lines.push("### OWASP Top 10 coverage");
    lines.push("");
    lines.push("| Category | Hits |");
    lines.push("|---|---:|");
    for (const [k, v] of Object.entries(byOwasp)) lines.push(`| ${k} | ${v} |`);
    lines.push("");
  }

  const byCwe = groupByCwe(findings);
  if (Object.keys(byCwe).length > 0) {
    lines.push("### Top CWEs");
    lines.push("");
    lines.push("| CWE | Hits |");
    lines.push("|---|---:|");
    for (const [k, v] of Object.entries(byCwe).slice(0, 10)) lines.push(`| ${k} | ${v} |`);
    lines.push("");
  }

  // Group by severity, then by file.
  const bySevMap: Record<Severity, SecurityFinding[]> = {
    critical: [],
    high: [],
    medium: [],
    low: [],
    info: [],
  };
  for (const f of findings) bySevMap[f.severity].push(f);

  for (const sev of SEVERITY_ORDER) {
    const group = bySevMap[sev];
    if (group.length === 0) continue;
    lines.push(`## ${sev.toUpperCase()} (${group.length})`);
    lines.push("");
    const byFile = new Map<string, SecurityFinding[]>();
    for (const f of group) {
      const arr = byFile.get(f.location.path) ?? [];
      arr.push(f);
      byFile.set(f.location.path, arr);
    }
    for (const [file, list] of byFile) {
      lines.push(`### \`${file}\``);
      for (const f of list) {
        const tags = [
          ...(f.cwe ?? []).map((c) => `\`${c}\``),
          ...(f.cve ?? []).map((c) => `\`${c}\``),
          ...(f.owasp ?? []).map((o) => `${o}`),
        ];
        const tagStr = tags.length > 0 ? ` — ${tags.join(", ")}` : "";
        lines.push(
          `- **${f.ruleId}** L${f.location.startLine}-L${f.location.endLine}${tagStr}: ${f.message}`,
        );
      }
      lines.push("");
    }
  }

  return lines.join("\n");
}
