/**
 * Shared aggregation helpers for the report engine.
 *
 * Re-exports the canonical aggregators from `compliance.ts` and adds
 * a few that are specific to the report layer (byCategory, byFile).
 */
import {
  groupByCwe,
  groupByOwasp,
  groupBySeverity,
  topRules,
} from "../compliance.js";
import type { Category, SecurityFinding } from "../findings.js";

/** Order in which the Category enum should be displayed in the by-category table. */
export const CATEGORY_ORDER: readonly Category[] = [
  "sast",
  "secret",
  "vuln",
  "config",
  "iac",
  "dependency",
  "container",
];

/** Count findings grouped by `category`. */
export function countByCategory(
  findings: SecurityFinding[],
): Record<string, number> {
  const out: Record<string, number> = Object.fromEntries(
    CATEGORY_ORDER.map((c) => [c, 0]),
  );
  for (const f of findings) {
    out[f.category] = (out[f.category] ?? 0) + 1;
  }
  // Drop zero entries to keep the table tight.
  return Object.fromEntries(Object.entries(out).filter(([, n]) => n > 0));
}

/** Group findings by repo-relative file path. */
export function groupByFile(
  findings: SecurityFinding[],
): Map<string, SecurityFinding[]> {
  const out = new Map<string, SecurityFinding[]>();
  for (const f of findings) {
    const list = out.get(f.location.path) ?? [];
    list.push(f);
    out.set(f.location.path, list);
  }
  return out;
}

/** True when the finding has an auto-applicable fix (non-empty diff). */
export function isAutoFixable(f: SecurityFinding): boolean {
  return !!f.fix && typeof f.fix.diff === "string" && f.fix.diff.length > 0;
}

export {
  groupByCwe,
  groupByOwasp,
  groupBySeverity,
  topRules,
};
