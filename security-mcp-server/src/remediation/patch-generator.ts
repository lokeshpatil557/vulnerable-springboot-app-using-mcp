/**
 * Patch generator. Given a finding + the current file contents, produces
 * a candidate fix as a unified diff. Priority:
 *   1. Semgrep's own `extra.fix` diff (if present)
 *   2. Rule template lookup (in `remediation/templates.ts`)
 *   3. `manual review required` fallback
 */
import type { SecurityFinding, FindingFix } from "../core/finding.js";

interface RuleTemplate {
  description: string;
  build: (original: string) => string;
}

const TEMPLATES: Record<string, RuleTemplate> = {
  "python.lang.security.audit.formatted-sql-query": {
    description: "Replace formatted SQL with a parameterized query.",
    build: () => "", // explicit refactor required; no auto-diff
  },
  "generic.sql.injection": {
    description: "Switch from string concatenation to a parameterized query.",
    build: () => "",
  },
};

export function proposeFix(finding: SecurityFinding, fileContents: string): FindingFix {
  // 1) Semgrep-provided fix
  if (finding.fix?.diff && finding.fix.diff.length > 0) {
    return {
      description: finding.fix.description ?? "Auto-fix from scanner.",
      diff: finding.fix.diff,
      confidence: "high",
    };
  }

  // 2) Rule template
  const tpl = TEMPLATES[finding.ruleId];
  if (tpl) {
    return {
      description: tpl.description,
      diff: tpl.build(fileContents),
      confidence: tpl.description.includes("refactor") ? "low" : "high",
    };
  }

  // 3) Manual review
  return {
    description: "Manual review required — no automated fix template for this rule.",
    diff: "",
    confidence: "low",
  };
}
