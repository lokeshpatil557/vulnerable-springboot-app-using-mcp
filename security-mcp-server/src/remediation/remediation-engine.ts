/**
 * Remediation engine: orchestrates propose → preview → apply → verify.
 * Keeps a small in-memory store of the latest scan so `generate_remediation`
 * and `apply_remediation` can resolve finding IDs.
 */
import { proposeFix } from "./patch-generator.js";
import { renderPrDescription } from "./pr-description-generator.js";
import type { SecurityFinding } from "../core/finding.js";
import { writeTextFileAtomic } from "../utils/file-utils.js";
import { sha256Hex } from "../utils/file-utils.js";
import { assertInsideRepo, safeJoin } from "../security/path-safety.js";
import { generateUnifiedDiff } from "./diff-generator.js";
import { join } from "node:path";

interface ScanRecord {
  id: string;
  findings: SecurityFinding[];
  repoRoot: string;
  startedAt: string;
}

export class RemediationEngine {
  private latest: ScanRecord | null = null;
  private history = new Map<string, ScanRecord>();

  recordScan(scan: ScanRecord): void {
    this.latest = scan;
    this.history.set(scan.id, scan);
  }

  getLatest(): ScanRecord | null {
    return this.latest;
  }

  getScan(id: string): ScanRecord | null {
    return this.history.get(id) ?? null;
  }

  propose(findingId: string, fileContents: string): { description: string; diff: string; confidence: "high" | "low" } | null {
    const scan = this.latest;
    if (!scan) return null;
    const finding = scan.findings.find((f) => f.fingerprint === findingId || f.id === findingId);
    if (!finding) return null;
    const fix = proposeFix(finding, fileContents);
    return { description: fix.description, diff: fix.diff, confidence: fix.confidence };
  }

  async apply(
    findingId: string,
    fileContents: string,
    options: { acknowledged: boolean; repoRoot: string }
  ): Promise<{ applied: boolean; backupPath: string; diff: string; rolledBack?: boolean }> {
    if (!options.acknowledged) {
      throw new Error("acknowledged: true is required to apply a remediation.");
    }
    const scan = this.latest;
    if (!scan) throw new Error("no scan recorded");
    const finding = scan.findings.find((f) => f.fingerprint === findingId || f.id === findingId);
    if (!finding) throw new Error("finding not found");
    const fix = proposeFix(finding, fileContents);
    if (!fix.diff) throw new Error("no automated fix available for this finding");
    const target = assertInsideRepo(options.repoRoot, finding.path);
    const backupDir = safeJoin(options.repoRoot, ".security-mcp", "backups", new Date().toISOString().replace(/[:.]/g, "-"));
    const backupPath = join(backupDir, target);
    const sha = await sha256Hex(fileContents);
    const staged = applyUnifiedDiff(fileContents, fix.diff);
    if (staged === null) {
      throw new Error("diff did not apply cleanly");
    }
    await writeTextFileAtomic(backupPath, fileContents);
    await writeTextFileAtomic(safeJoin(options.repoRoot, target), staged);
    return { applied: true, backupPath, diff: generateUnifiedDiff(fileContents, staged, target) };
  }

  renderPr(scanId?: string): string | null {
    const scan = scanId ? this.history.get(scanId) : this.latest;
    if (!scan) return null;
    return renderPrDescription(scan.findings, {
      repo: scan.repoRoot,
      scanId: scan.id,
      generatedAt: scan.startedAt,
    });
  }
}

/** Tiny, conservative unified-diff applier. Returns null if the patch can't apply. */
export function applyUnifiedDiff(original: string, patch: string): string | null {
  // Naive line-by-line applet: the scanner usually produces a patch where
  // the *file* field equals the path. We require the original to match the
  // patch's "before" segment; otherwise bail.
  if (!patch) return original;
  const lines = original.split(/\r?\n/);
  const patchLines = patch.split(/\r?\n/);
  let i = 0;
  let pi = 0;
  while (pi < patchLines.length) {
    const h = patchLines[pi];
    if (!h || h.startsWith("Index:") || h.startsWith("===") || h.startsWith("---") || h.startsWith("+++") || h.startsWith("@@")) {
      pi++;
      continue;
    }
    const tag = h[0];
    const text = h.slice(1);
    if (tag === " ") {
      if (lines[i] !== text) return null;
      i++;
      pi++;
    } else if (tag === "-") {
      if (lines[i] !== text) return null;
      i++;
      pi++;
    } else if (tag === "+") {
      lines.splice(i, 0, text);
      i++;
      pi++;
    } else {
      pi++;
    }
  }
  return lines.join("\n");
}

export type { ScanRecord };
