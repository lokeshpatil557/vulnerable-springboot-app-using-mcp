import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { ToolContext, AnyMcpServer } from "./_shared.js";
import { z, auditWrap, ok } from "./_shared.js";
import { proposeRemediation } from "../remediation.js";
import { generateUnifiedDiff } from "../diff.js";
import { assertInsideRepo } from "../paths.js";
import { RemediationNotFoundError } from "../errors.js";

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
    "generate_remediation",
    "Generate a unified-diff remediation for a single finding. Read-only — does not modify files. " +
      "Use apply_remediation to actually apply the change. Priority: Semgrep's own fix -> rule template -> manual review.",
    {
      findingId: z.string().min(1).max(256),
      filePath: z.string().min(1).max(4096),
      ruleId: z.string().min(1).max(512),
      message: z.string().min(1).max(8192),
      startLine: z.number().int().positive().optional(),
      fixDescription: z.string().optional(),
      fixDiff: z.string().optional(),
    },
    async (args) =>
      auditWrap(ctx, "generate_remediation", args, async () => {
        const a = args as {
          findingId: string;
          filePath: string;
          ruleId: string;
          message: string;
          startLine?: number;
          fixDescription?: string;
          fixDiff?: string;
        };
        const abs = assertInsideRepo(ctx.repoRoot, a.filePath);
        let contents = "";
        try {
          contents = await readFile(abs, "utf8");
        } catch {
          contents = "";
        }
        const finding = {
          id: a.findingId,
          ruleId: a.ruleId,
          level: "warning" as const,
          severity: "medium" as const,
          message: a.message,
          location: { path: a.filePath, startLine: a.startLine ?? 0, endLine: a.startLine ?? 0 },
          cwe: [],
          category: "sast" as const,
          tool: { name: "semgrep" as const },
          fingerprint: a.findingId,
        };
        if (a.fixDiff) {
          finding.fix = { description: a.fixDescription ?? "Semgrep fix", diff: a.fixDiff };
        }
        const proposal = proposeRemediation(finding, contents);
        // Persist for apply_remediation.
        const id = a.findingId;
        const record: StoredRemediation = {
          findingId: id,
          ruleId: a.ruleId,
          filePath: abs,
          description: proposal.description,
          diff: proposal.diff,
          confidence: proposal.confidence,
          source: proposal.source,
          createdAt: new Date().toISOString(),
        };
        const dir = join(ctx.repoRoot, ".security-mcp", "remediations");
        await import("../util/fs.js").then((m) => m.writeTextFileAtomic(join(dir, `${id}.json`), JSON.stringify(record, null, 2)));
        // Always return a diff string (possibly the full-file diff for manual fallback).
        const finalDiff = proposal.diff || generateUnifiedDiff(a.filePath, contents, contents);
        return ok({
          findingId: a.findingId,
          description: proposal.description,
          diff: finalDiff,
          confidence: proposal.confidence,
          source: proposal.source,
        });
      }),
  );
}
