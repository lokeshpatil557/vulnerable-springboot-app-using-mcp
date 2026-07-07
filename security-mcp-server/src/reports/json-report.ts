/** JSON report — full findings with metadata. */
import type { SecurityFinding } from "../core/finding.js";
import type { ReportMeta } from "./report-engine.js";

export function renderJsonReport(findings: SecurityFinding[], meta: ReportMeta): string {
  return JSON.stringify(
    {
      meta,
      findings,
      counts: {
        total: findings.length,
        bySeverity: countBy(findings, (f) => f.severity),
        byCategory: countBy(findings, (f) => f.category),
      },
    },
    null,
    2
  );
}

function countBy<T, K extends string>(arr: T[], fn: (x: T) => K): Record<string, number> {
  const out: Record<string, number> = {};
  for (const x of arr) {
    const k = fn(x);
    out[k] = (out[k] ?? 0) + 1;
  }
  return out;
}
