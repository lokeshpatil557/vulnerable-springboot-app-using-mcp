/**
 * Renders a markdown PR description summarizing the proposed remediation batch.
 * Inputs are simple, structured data so the output is deterministic and
 * testable without involving the LLM.
 */
import type { SecurityFinding } from "../core/finding.js";
import { severityEmoji } from "../core/severity.js";

export function renderPrDescription(findings: SecurityFinding[], context: {
  repo: string;
  scanId: string;
  generatedAt: string;
}): string {
  const header = `# Security remediation\n\nGenerated ${context.generatedAt} for \`${context.repo}\` (scan \`${context.scanId}\`).`;
  const counts = countBySeverity(findings);
  const table =
    "| Severity | Count |\n|---|---|\n" +
    (["critical", "high", "medium", "low", "info"] as const)
      .map((s) => `| ${severityEmoji(s)} ${s} | ${counts[s] ?? 0} |`)
      .join("\n");
  const top = findings
    .slice()
    .sort((a, b) => severityRank(b.severity) - severityRank(a.severity))
    .slice(0, 10)
    .map(formatFindingLine)
    .join("\n");
  const checklist =
    "\n## Checklist\n\n" +
    "- [ ] Review every critical/high finding before merge\n" +
    "- [ ] Confirm tests still pass after applied fixes\n" +
    "- [ ] Audit the `.security-mcp/backups/` for any uncommitted rollbacks\n" +
    "- [ ] Re-run `scan_repository` and verify `verify_fix` returns `fixed` for all applied IDs\n";

  return `${header}\n\n## Summary\n\n${table}\n\n## Top findings\n\n${top}\n${checklist}`;
}

function countBySeverity(findings: SecurityFinding[]): Record<string, number> {
  const out: Record<string, number> = {};
  for (const f of findings) out[f.severity] = (out[f.severity] ?? 0) + 1;
  return out;
}

function severityRank(s: SecurityFinding["severity"]): number {
  return { critical: 4, high: 3, medium: 2, low: 1, info: 0 }[s] ?? 0;
}

function formatFindingLine(f: SecurityFinding): string {
  return `- ${severityEmoji(f.severity)} **${f.ruleId}** — \`${f.location.path}:${f.location.startLine}\` — ${f.message}`;
}
