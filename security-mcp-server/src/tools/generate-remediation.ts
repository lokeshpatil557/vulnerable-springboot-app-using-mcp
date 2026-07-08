import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { ToolContext, AnyMcpServer } from "./_shared.js";
import { z, auditWrap, ok } from "./_shared.js";
import { proposeRemediation, buildGuidance, buildUnifiedDiff, type RemediationGuidance } from "../remediation.js";
import { guardRemediationFile, guardDiffPayload, policyFromConfig } from "../security/path-safety.js";
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
  /** Rich per-finding guidance (items 1-10 of the remediation spec).
   *  Read-only; `apply_remediation` ignores this field. */
  guidance?: RemediationGuidance;
}

export function register(server: AnyMcpServer, ctx: ToolContext): void {
  server.tool(
    "generate_remediation",
    "Generate a structured remediation for a single finding. Read-only — does not modify files. " +
      "Returns a 10-field guidance object (vulnerability explanation, exploit scenario, impact, " +
      "severity reasoning, secure recommendation, code guidance, patch suggestion, unified diff, " +
      "PR description, and verification steps) alongside the existing unified diff. " +
      "Use apply_remediation to actually apply the change. Priority: Semgrep's own fix -> rule template -> manual review.",
    {
      findingId: z.string().min(1).max(256),
      filePath: z.string().min(1).max(4096),
      ruleId: z.string().min(1).max(512),
      message: z.string().min(1).max(8192),
      startLine: z.number().int().positive().optional(),
      fixDescription: z.string().optional(),
      fixDiff: z.string().optional(),
      includeGuidance: z.boolean().optional().default(true),
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
          includeGuidance?: boolean;
        };
        const includeGuidance = a.includeGuidance !== false;
        const policy = policyFromConfig(ctx.config.pathSafety, ctx.repoRoot);
        // Enforce all path-safety checks: 1 (allowed root), 2 (no
        // traversal), 3 (no symlink escape), 4 (no home/root),
        // 5 (no binary for remediation), 6 (size caps).
        const guarded = await guardRemediationFile(
          ctx.repoRoot,
          a.filePath,
          policy,
          { tool: "generate_remediation" },
        );
        const abs = guarded.absPath;
        // Also cap the inbound fixDiff payload (requirement 6).
        if (a.fixDiff) {
          guardDiffPayload(a.fixDiff, policy, { tool: "generate_remediation" });
        }
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
          (finding as { fix?: { description: string; diff: string } }).fix = {
            description: a.fixDescription ?? "Semgrep fix",
            diff: a.fixDiff,
          };
        }
        const proposal = proposeRemediation(finding, contents);

        // Build the rich guidance. The tool never mutates files; the
        // `apply_remediation` path reads the same on-disk record.
        let guidance: RemediationGuidance | undefined;
        if (includeGuidance) {
          // We pass the (possibly empty) old contents to the guidance
          // module. `buildUnifiedDiff` produces the actual diff text from
          // the original contents; the guidance module cannot compute it
          // on its own because it has no access to the proposed new
          // contents (that would require running `proposeRemediation`).
          const proposalAsFinding = { ...finding } as Parameters<typeof buildGuidance>[0];
          if (a.fixDiff) {
            (proposalAsFinding as { fix?: { description: string; diff: string } }).fix = {
              description: a.fixDescription ?? "Semgrep fix",
              diff: a.fixDiff,
            };
          }
          // The proposal may have produced a non-empty diff (when a rule
          // template fired). When it did, the guidance's `diff` field
          // should be that diff; otherwise the field stays empty.
          const guidanceDiff = proposal.diff || "";
          const built = buildGuidance(proposalAsFinding, contents, { now: new Date() });
          guidance = { ...built, diff: guidanceDiff };
        }

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
        if (guidance) record.guidance = guidance;
        const dir = join(ctx.repoRoot, ".security-mcp", "remediations");
        await import("../util/fs.js").then((m) =>
          m.writeTextFileAtomic(join(dir, `${id}.json`), JSON.stringify(record, null, 2)),
        );
        // Always return a diff string (possibly the full-file diff for manual fallback).
        const finalDiff = proposal.diff || buildUnifiedDiff(a.filePath, contents, contents);
        const result: Record<string, unknown> = {
          findingId: a.findingId,
          description: proposal.description,
          diff: finalDiff,
          confidence: proposal.confidence,
          source: proposal.source,
        };
        if (guidance) {
          result.guidance = guidance;
        }
        return ok(result);
      }),
  );
}
