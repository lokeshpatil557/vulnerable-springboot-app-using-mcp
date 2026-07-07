import type { ToolContext, AnyMcpServer } from "./_shared.js";
import { z, auditWrap, ok } from "./_shared.js";
import { runScanners } from "../scanners/registry.js";
import { readdir, readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import type { SecurityFinding } from "../findings.js";

interface StoredScan {
  meta: { scanId: string };
  findings: SecurityFinding[];
}

export function register(server: AnyMcpServer, ctx: ToolContext): void {
  server.tool(
    "verify_fix",
    "Re-run scanners and confirm whether the listed finding IDs are still present. " +
      "Each result is `fixed`, `still_present`, or `not_found_in_storage`.",
    {
      findingIds: z.array(z.string().min(1).max(256)).min(1).max(100),
    },
    async (args) =>
      auditWrap(ctx, "verify_fix", args, async () => {
        const a = args as { findingIds: string[] };
        // Find the most recent scan that contains these finding IDs.
        const dir = join(ctx.repoRoot, ".security-mcp", "scans");
        const fingerprints = new Set<string>();
        try {
          const entries = await readdir(dir);
          const files = (await Promise.all(
            entries.map(async (e) => {
              const full = join(dir, e);
              const s = await stat(full);
              return s.isFile() ? { full, mtime: s.mtimeMs } : null;
            }),
          )).filter((x): x is { full: string; mtime: number } => x !== null);
          files.sort((a, b) => b.mtime - a.mtime);
          for (const f of files) {
            try {
              const j = JSON.parse(await readFile(f.full, "utf8")) as StoredScan;
              for (const finding of j.findings ?? []) {
                if (a.findingIds.includes(finding.id)) fingerprints.add(finding.id);
              }
            } catch {
              // ignore
            }
          }
        } catch {
          // no scans yet
        }
        // Re-run a fresh scan.
        const res = await runScanners(
          { root: ctx.repoRoot, config: ctx.config, logger: ctx.logger },
          ctx.scanners,
          {},
          ctx.logger,
        );
        const liveIds = new Set(res.findings.map((f) => f.id));
        const results = a.findingIds.map((id) => ({
          findingId: id,
          status: !fingerprints.has(id)
            ? ("not_found_in_storage" as const)
            : liveIds.has(id)
              ? ("still_present" as const)
              : ("fixed" as const),
        }));
        return ok({ results, durationMs: res.durationMs });
      }),
  );
}
