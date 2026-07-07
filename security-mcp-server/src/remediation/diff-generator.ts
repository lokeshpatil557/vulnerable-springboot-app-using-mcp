/**
 * Generate a unified diff for a finding.
 * Pure, side-effect-free: returns the diff text without touching the filesystem.
 */
import { createPatch } from "diff";
import type { SecurityFinding, FindingFix } from "../core/finding.js";

export function generateUnifiedDiff(
  original: string,
  modified: string,
  path: string
): string {
  // createPatch returns text ending with a newline.
  return createPatch(path, original, modified, "before", "after", { context: 3 });
}

export function diffFromFinding(finding: SecurityFinding, original: string): string | null {
  if (!finding.fix?.diff) return null;
  // We only need to know whether the diff *applies* — the unified text is the fix.
  return finding.fix.diff;
}

export function emptyFix(message: string): FindingFix {
  return { description: message, diff: "", confidence: "low" };
}
