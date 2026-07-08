import { lookupTemplate, type RemediationTemplate } from "./rules/index.js";
import { generateUnifiedDiff } from "./diff.js";
import type { SecurityFinding } from "./findings.js";

// Re-export the guidance module so the tool layer can import both
// `proposeRemediation` and `buildGuidance` from a single entry point.
// `buildGuidance` is read-only and never mutates files.
export {
  buildGuidance,
  buildUnifiedDiff,
  type RemediationGuidance,
  type BuildGuidanceOptions,
  type PatchSuggestion,
  type VerificationPlan,
  type ImpactAssessment,
} from "./remediation/guidance.js";

export interface RemediationProposal {
  findingId: string;
  ruleId: string;
  description: string;
  diff: string;
  confidence: "high" | "low";
  source: "semgrep_fix" | "template" | "manual";
}

/**
 * Produce a remediation proposal for a single finding.
 *
 * Priority:
 *   1. Use Semgrep's own `extra.fix` diff if it is present and parseable.
 *   2. Look up a `RemediationTemplate` by `ruleId` (or ruleIdPrefix).
 *   3. Fall back to "manual review required".
 *
 * Never mutates files. Callers must explicitly invoke `apply_remediation`.
 */
export function proposeRemediation(
  finding: SecurityFinding,
  fileContents: string,
): RemediationProposal {
  // 1. Semgrep-provided fix diff.
  if (finding.fix?.diff && finding.fix.diff.length > 0) {
    return {
      findingId: finding.id,
      ruleId: finding.ruleId,
      description: finding.fix.description || "Semgrep-provided fix",
      diff: finding.fix.diff,
      confidence: "high",
      source: "semgrep_fix",
    };
  }

  // 2. Template lookup.
  const tpl = lookupTemplate(finding.ruleId);
  if (tpl) {
    const { description, replacement, anchor } = applyTemplate(tpl, fileContents);
    if (replacement !== null) {
      const modified = applyAnchorReplace(fileContents, anchor, replacement);
      const diff = generateUnifiedDiff(finding.location.path, fileContents, modified);
      return {
        findingId: finding.id,
        ruleId: finding.ruleId,
        description,
        diff,
        confidence: "high",
        source: "template",
      };
    }
  }

  // 3. Manual fallback.
  return {
    findingId: finding.id,
    ruleId: finding.ruleId,
    description:
      "No automated fix template is available for this rule. " +
      "Please review the finding and apply a manual fix.",
    diff: "",
    confidence: "low",
    source: "manual",
  };
}

function applyTemplate(
  tpl: RemediationTemplate,
  fileContents: string,
): { description: string; replacement: string | null; anchor: string } {
  if (tpl.kind === "literal-replace") {
    if (fileContents.includes(tpl.needle)) {
      return {
        description: tpl.description,
        replacement: tpl.replacement,
        anchor: tpl.needle,
      };
    }
    return { description: tpl.description, replacement: null, anchor: tpl.needle };
  }
  if (tpl.kind === "regex-replace") {
    if (new RegExp(tpl.pattern).test(fileContents)) {
      return {
        description: tpl.description,
        replacement: tpl.replacement,
        anchor: tpl.pattern,
      };
    }
    return { description: tpl.description, replacement: null, anchor: tpl.pattern };
  }
  // Exhaustiveness — should be unreachable since `RemediationTemplate.kind`
  // is a closed set, but provide a safe default for forward-compat.
  const fallback = tpl as { description?: string };
  return { description: fallback.description ?? "", replacement: null, anchor: "" };
}

function applyAnchorReplace(contents: string, anchor: string, replacement: string): string {
  if (!anchor) return contents;
  if (anchor.includes("\\") || anchor.includes(".*") || anchor.includes("[")) {
    return contents.replace(new RegExp(anchor, "g"), replacement);
  }
  return contents.split(anchor).join(replacement);
}
