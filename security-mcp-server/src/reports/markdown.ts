/**
 * Markdown report — 8-section format for human / GitHub PR consumption.
 *
 *   1. Executive summary
 *   2. Finding count by severity
 *   3. Finding count by category
 *   4. Technology stack detected
 *   5. Critical and high findings
 *   6. Detailed findings (grouped by file)
 *   7. Remediation summary
 *   8. Verification checklist
 */
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, join } from "node:path";
import {
  CATEGORY_ORDER,
  countByCategory,
  groupByFile,
  isAutoFixable,
  topRules,
} from "./summary.js";
import { severityEmoji, type Severity } from "../core/severity.js";
import { detectCodebase } from "../core/codebase-detector.js";
import type { SecurityFinding } from "../findings.js";
import type { ReportMeta } from "./json.js";

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export async function writeMarkdownReport(
  findings: SecurityFinding[],
  destPath: string,
  meta: ReportMeta,
): Promise<string> {
  // Pre-detect the tech stack so the renderer can emit section 4.
  // Detection failures are silently absorbed — section 4 is informational.
  let detected: Awaited<ReturnType<typeof detectCodebase>> = [];
  try {
    detected = await detectCodebase(meta.repoRoot);
  } catch {
    detected = [];
  }
  const md = renderMarkdown(findings, meta, detected);
  const abs = isAbsolute(destPath) ? destPath : join(meta.repoRoot, destPath);
  await mkdir(dirname(abs), { recursive: true });
  await writeFile(abs, md, "utf8");
  return abs;
}

export function renderMarkdown(
  findings: SecurityFinding[],
  meta: ReportMeta,
  detected: Awaited<ReturnType<typeof detectCodebase>> = [],
): string {
  const lines: string[] = [];

  // ---------- Header / metadata ----------
  lines.push(`# Security report — ${meta.scanId}`);
  lines.push("");
  lines.push(`- Repository: \`${meta.repoRoot}\``);
  lines.push(`- Started: ${meta.startedAt}`);
  lines.push(`- Finished: ${meta.finishedAt}`);
  lines.push(`- Duration: ${meta.durationMs}ms`);
  lines.push(
    `- Scanners: ${
      Object.entries(meta.scannerVersions)
        .map(([k, v]) => `${k}@${v ?? "?"}`)
        .join(", ") || "(none)"
    }`,
  );
  lines.push("");

  // ---------- Section 1: Executive summary ----------
  lines.push("## 1. Executive summary");
  lines.push("");
  lines.push(execSummary(findings, meta));
  lines.push("");

  // ---------- Section 2: Finding count by severity ----------
  lines.push("## 2. Finding count by severity");
  lines.push("");
  lines.push("| Severity | Count |");
  lines.push("|---|---:|");
  for (const s of SEVERITY_ORDER) {
    const n = findings.filter((f) => f.severity === s).length;
    lines.push(`| ${severityEmoji(s)} ${s} | ${n} |`);
  }
  lines.push(`| **Total** | **${findings.length}** |`);
  lines.push("");

  // ---------- Section 3: Finding count by category ----------
  lines.push("## 3. Finding count by category");
  lines.push("");
  const byCategory = countByCategory(findings);
  if (Object.keys(byCategory).length === 0) {
    lines.push("_No findings._");
    lines.push("");
  } else {
    lines.push("| Category | Count |");
    lines.push("|---|---:|");
    for (const c of CATEGORY_ORDER) {
      if (byCategory[c] === undefined) continue;
      lines.push(`| ${c} | ${byCategory[c]} |`);
    }
    lines.push("");
  }

  // ---------- Section 4: Technology stack detected ----------
  lines.push("## 4. Technology stack detected");
  lines.push("");
  if (detected.length === 0) {
    lines.push("_No technology detected (or detection plugins unavailable)._");
    lines.push("");
  } else {
    lines.push("| Technology | Confidence | Evidence |");
    lines.push("|---|---:|---|");
    for (const m of detected) {
      const evidence = m.evidence?.join(", ") ?? "—";
      lines.push(
        `| ${m.displayName} | ${(m.confidence * 100).toFixed(0)}% | ${evidence} |`,
      );
    }
    lines.push("");
  }

  // ---------- Section 5: Critical and high findings ----------
  lines.push("## 5. Critical and high findings");
  lines.push("");
  const criticals = findings.filter((f) => f.severity === "critical");
  const highs = findings.filter((f) => f.severity === "high");
  if (criticals.length === 0 && highs.length === 0) {
    lines.push("✅ No critical or high severity findings.");
    lines.push("");
  } else {
    let idx = 1;
    for (const f of [...criticals, ...highs]) {
      lines.push(renderFindingCard(idx++, f, /* detailed */ true));
    }
  }

  // ---------- Section 6: Detailed findings (all, grouped by file) ----------
  lines.push("## 6. Detailed findings");
  lines.push("");
  if (findings.length === 0) {
    lines.push("_No findings._");
    lines.push("");
  } else {
    const byFile = groupByFile(findings);
    const sortedFiles = [...byFile.keys()].sort();
    for (const file of sortedFiles) {
      const list = byFile.get(file)!;
      lines.push(`### \`${file}\``);
      lines.push("");
      for (const f of list) {
        const tags = [
          severityEmoji(f.severity),
          f.severity,
          ...(f.cwe ?? []).map((c) => `\`${c}\``),
          ...(f.cve ?? []).map((c) => `\`${c}\``),
        ];
        lines.push(
          `- **${f.ruleId}** L${f.location.startLine}-L${f.location.endLine ?? f.location.startLine} [${tags.join(" · ")}]: ${f.message}`,
        );
      }
      lines.push("");
    }
  }

  // ---------- Section 7: Remediation summary ----------
  lines.push("## 7. Remediation summary");
  lines.push("");
  const auto = findings.filter(isAutoFixable);
  const manual = findings.filter((f) => !isAutoFixable(f));
  const top = topRules(findings, 5);
  lines.push(`- **Auto-fixable:** ${auto.length} of ${findings.length} findings (have a non-empty \`fix.diff\`).`);
  lines.push(`- **Manual review:** ${manual.length} of ${findings.length} findings (no automated patch).`);
  lines.push("");
  if (top.length > 0) {
    lines.push("### Top recurring rules");
    lines.push("");
    lines.push("| Rule | Hits | Auto-fixable |");
    lines.push("|---|---:|---:|");
    for (const r of top) {
      const hits = findings.filter((f) => f.ruleId === r.ruleId);
      const af = hits.filter(isAutoFixable).length;
      lines.push(`| \`${r.ruleId}\` | ${r.count} | ${af} |`);
    }
    lines.push("");
  }
  if (auto.length > 0) {
    lines.push("### Auto-fixable findings");
    lines.push("");
    for (const f of auto) {
      lines.push(
        `- \`${f.location.path}\` L${f.location.startLine} — \`${f.ruleId}\`: ${f.fix?.description ?? "(see diff)"}`,
      );
    }
    lines.push("");
  }

  // ---------- Section 8: Verification checklist ----------
  lines.push("## 8. Verification checklist");
  lines.push("");
  lines.push("- [ ] Re-run the security scan to confirm no regression");
  lines.push("- [ ] Triage the top 5 rules by frequency");
  lines.push("- [ ] Apply high/critical fixes first");
  lines.push("- [ ] Run `apply_remediation` for every auto-fixable finding");
  lines.push("- [ ] Call `verify_fix` for each applied remediation");
  lines.push("- [ ] Update the affected unit tests");
  lines.push("- [ ] Document any deferred / accepted-risk findings");
  lines.push("- [ ] Re-scan and confirm zero new findings");
  lines.push("");

  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Headline narrative for section 1. */
function execSummary(findings: SecurityFinding[], meta: ReportMeta): string {
  const critical = findings.filter((f) => f.severity === "critical").length;
  const high = findings.filter((f) => f.severity === "high").length;
  const total = findings.length;
  if (total === 0) {
    return `Scan \`${meta.scanId}\` of \`${meta.repoRoot}\` found **no issues**.`;
  }
  const parts: string[] = [];
  parts.push(
    `Scan \`${meta.scanId}\` of \`${meta.repoRoot}\` found **${total}** issue(s).`,
  );
  if (critical > 0 || high > 0) {
    parts.push(
      `⚠️ **Action required:** ${critical} critical and ${high} high-severity finding(s) need immediate attention.`,
    );
  } else {
    parts.push("No critical or high-severity findings detected.");
  }
  const auto = findings.filter(isAutoFixable).length;
  if (auto > 0) {
    parts.push(
      `${auto} of ${total} finding(s) have an automated fix available — see Section 7.`,
    );
  }
  return parts.join(" ");
}

/** Render one finding as a numbered card (used by section 5). */
function renderFindingCard(
  idx: number,
  f: SecurityFinding,
  detailed: boolean,
): string {
  const out: string[] = [];
  out.push(`### ${idx}. ${severityEmoji(f.severity)} \`${f.ruleId}\` — ${f.severity}`);
  out.push("");
  out.push(`- **Location:** \`${f.location.path}\` L${f.location.startLine}-L${f.location.endLine ?? f.location.startLine}`);
  out.push(`- **Message:** ${f.message}`);
  out.push(`- **Category:** ${f.category}`);
  if (f.cwe?.length) out.push(`- **CWE:** ${f.cwe.join(", ")}`);
  if (f.cve?.length) out.push(`- **CVE:** ${f.cve.join(", ")}`);
  if (f.owasp?.length) out.push(`- **OWASP:** ${f.owasp.join(", ")}`);
  if (f.references?.length) out.push(`- **References:** ${f.references.join(", ")}`);
  if (f.fix?.description) {
    out.push(`- **Fix:** ${f.fix.description}${f.fix.diff ? " (auto-applicable)" : " (manual review)"}`);
  } else {
    out.push(`- **Fix:** _manual review required_`);
  }
  out.push(`- **Fingerprint:** \`${f.fingerprint}\``);
  if (detailed && f.fix?.diff) {
    out.push("");
    out.push("```diff");
    out.push(f.fix.diff);
    out.push("```");
  }
  out.push("");
  return out.join("\n");
}
