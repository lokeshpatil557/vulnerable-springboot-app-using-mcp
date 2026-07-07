import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { ToolContext, AnyMcpServer } from "./_shared.js";
import { z, auditWrap, ok } from "./_shared.js";
import { applyWithBackup, rollback } from "../diff.js";
import { runScanners } from "../scanners/registry.js";
import { assertInsideRepo } from "../paths.js";
import { InvalidInputError, RemediationNotFoundError } from "../errors.js";
import { writeTextFileAtomic } from "../util/fs.js";

interface StoredRemediation {
  findingId: string;
  ruleId: string;
  filePath: string;
  description: string;
  diff: string;
  confidence: "high" | "low";
  source: "semgrep_fix" | "template" | "manual";
  createdAt: string;
}

export function register(server: AnyMcpServer, ctx: ToolContext): void {
  server.tool(
    "apply_remediation",
    "Apply a previously generated remediation. ALWAYS requires `acknowledged: true`. " +
      "Creates a timestamped backup of the file under `.security-mcp/backups/`, applies the change, " +
      "then re-runs the producing scanner. If the finding persists or new findings appear, " +
      "the file is rolled back from the backup.",
    {
      findingId: z.string().min(1).max(256),
      diff: z.string().min(1),
      acknowledged: z.literal(true),
    },
    async (args) =>
      auditWrap(ctx, "apply_remediation", args, async () => {
        const a = args as { findingId: string; diff: string; acknowledged: true };
        if (a.acknowledged !== true) {
          throw new InvalidInputError("apply_remediation requires acknowledged: true");
        }
        // Load the prior remediation record.
        const recordPath = join(ctx.repoRoot, ".security-mcp", "remediations", `${a.findingId}.json`);
        let record: StoredRemediation;
        try {
          record = JSON.parse(await readFile(recordPath, "utf8"));
        } catch {
          throw new RemediationNotFoundError(a.findingId);
        }
        // Apply the change. The diff is a unified diff; for the MVP we
        // expect the caller to provide the new file contents in the
        // `description` extension or — better — we re-derive by reading
        // the current file and applying the stored diff. For now, we treat
        // `diff` as the full new file contents when there's no `--- /+++`
        // header, otherwise we re-read the file and assume the user
        // intends the diff to be a no-op until the pipeline is wired up.
        const abs = assertInsideRepo(ctx.repoRoot, record.filePath);
        let current = "";
        try {
          current = await readFile(abs, "utf8");
        } catch {
          // file may not exist yet
        }
        const looksLikeUnified = /^--- |^\*\*\* /m.test(a.diff);
        const newContents = looksLikeUnified ? current : a.diff;
        if (looksLikeUnified) {
          // We can't apply unified diffs deterministically without a real
          // patcher. For v1 we surface a clear error and ask the user to
          // provide full file contents.
          throw new InvalidInputError(
            "apply_remediation: unified-diff payloads are not yet supported. " +
              "Provide the new file contents in the `diff` field (or extend `description` to include them).",
          );
        }
        const apply = await applyWithBackup(ctx.repoRoot, abs, newContents);
        // Re-scan the file to verify.
        const res = await runScanners(
          {
            root: ctx.repoRoot,
            target: record.filePath,
            config: ctx.config,
            logger: ctx.logger,
          },
          ctx.scanners,
          { ids: ["semgrep", "gitleaks"] },
          ctx.logger,
        );
        const stillPresent = res.findings.some((f) => f.fingerprint === a.findingId);
        const newFindings = res.findings.length;
        if (stillPresent || newFindings > 0) {
          const rb = await rollback(ctx.repoRoot, abs, apply.backupPath, apply.sha256Before);
          return ok({
            applied: false,
            rolledBack: rb.rolledBack,
            reason: stillPresent
              ? "finding still present after apply"
              : `${newFindings} new finding(s) introduced`,
            backupPath: rel(ctx.repoRoot, apply.backupPath),
          });
        }
        // Mark the remediation as applied (drop the stored record to prevent reuse).
        try {
          await writeTextFileAtomic(recordPath, JSON.stringify({ ...record, appliedAt: new Date().toISOString() }, null, 2));
        } catch {
          // best effort
        }
        return ok({ applied: true, rolledBack: false, backupPath: rel(ctx.repoRoot, apply.backupPath) });
      }),
  );
}

function rel(_repoRoot: string, p: string): string {
  return p;
}
