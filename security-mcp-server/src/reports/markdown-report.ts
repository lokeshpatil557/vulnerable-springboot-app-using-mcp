/** Markdown report — severity-grouped, then by file. */
import type { SecurityFinding } from "../core/finding.js";
import { severityEmoji } from "../core/severity.js";
import type { ReportMeta } from "./report-engine.js";

export function renderMarkdownReport(findings: SecurityFinding[], meta: ReportMeta): string {
  const grouped = groupByFile(findings);
  const counts = countBySeverity(findings);
  const lines: string[] = [];
  lines.push(`# Security report`);
  lines.push("");
  lines.push(`- Scan: \`${meta.scanId}\``);
  lines.push(`- Repo: \`${meta.repoRoot}\``);
  lines.push(`- Started: ${meta.startedAt}`);
  lines.push(`- Finished: ${meta.finishedAt}`);
  lines.push(`- Scanners: ${Object.entries(meta.scannerVersions).map(([k, v]) => `${k}@${v}`).join(", ") || "(none)"}`);
  lines.push("");
  lines.push("## Summary");
  lines.push("");
  lines.push("| Severity | Count |");
  lines.push("|---|---|");
  for (const s of ["critical", "high", "medium", "low", "info"] as const) {
    lines.push(`| ${severityEmoji(s)} ${s} | ${counts[s] ?? 0} |`);
  }
  lines.push("");
  lines.push(`Total: ${findings.length} findings.`);
  lines.push("");
  for (const [file, items] of Object.entries(grouped)) {
    lines.push(`## ${file}`);
    lines.push("");
    for (const f of items) {
      lines.push(`### ${severityEmoji(f.severity)} ${f.ruleId} (${f.severity})`);
      lines.push("");
      lines.push(`- Location: line ${f.location.startLine}${f.location.endLine ? `–${f.location.endLine}` : ""}`);
      lines.push(`- Category: ${f.category}`);
      if (f.cwe.length) lines.push(`- CWE: ${f.cwe.join(", ")}`);
      if (f.cve?.length) lines.push(`- CVE: ${f.cve.join(", ")}`);
      if (f.owasp?.length) lines.push(`- OWASP: ${f.owasp.join(", ")}`);
      lines.push(`- Confidence: ${f.fix?.confidence ?? "n/a"}`);
      lines.push(`- Message: ${f.message}`);
      if (f.fix?.description) lines.push(`- Fix: ${f.fix.description}`);
      lines.push(`- Fingerprint: \`${f.fingerprint}\``);
      lines.push("");
    }
  }
  return lines.join("\n");
}

function countBySeverity(findings: SecurityFinding[]): Record<string, number> {
  const out: Record<string, number> = {};
  for (const f of findings) out[f.severity] = (out[f.severity] ?? 0) + 1;
  return out;
}

function groupByFile(findings: SecurityFinding[]): Record<string, SecurityFinding[]> {
  const out: Record<string, SecurityFinding[]> = {};
  for (const f of findings) {
    (out[f.location.path] ||= []).push(f);
  }
  return out;
}
