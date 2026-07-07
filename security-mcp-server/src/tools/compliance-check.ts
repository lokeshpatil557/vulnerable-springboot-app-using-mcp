import { readFile, readdir, stat } from "node:fs/promises";
import { join } from "node:path";
import type { ToolContext, AnyMcpServer } from "./_shared.js";
import { z, auditWrap, ok } from "./_shared.js";
import { groupByCwe, groupByOwasp, groupBySeverity } from "../compliance.js";
import type { SecurityFinding } from "../findings.js";

interface StoredScan {
  meta: { scanId: string; startedAt: string; finishedAt: string };
  findings: SecurityFinding[];
}

export function register(server: AnyMcpServer, ctx: ToolContext): void {
  server.tool(
    "compliance_check",
    "Aggregate findings by OWASP Top 10, CWE, and severity. Defaults to the most recent persisted scan.",
    {
      scanId: z.string().optional(),
    },
    async (args) =>
      auditWrap(ctx, "compliance_check", args, async () => {
        const a = args as { scanId?: string };
        const findings = a.scanId
          ? await loadScan(ctx.repoRoot, a.scanId)
          : await loadLatestScan(ctx.repoRoot);
        return ok({
          total: findings.length,
          bySeverity: groupBySeverity(findings),
          byOwasp: groupByOwasp(findings),
          byCwe: groupByCwe(findings),
        });
      }),
  );
}

async function loadScan(repoRoot: string, scanId: string): Promise<SecurityFinding[]> {
  const p = join(repoRoot, ".security-mcp", "scans", `${scanId}.json`);
  const j = JSON.parse(await readFile(p, "utf8")) as StoredScan;
  return j.findings ?? [];
}

async function loadLatestScan(repoRoot: string): Promise<SecurityFinding[]> {
  const dir = join(repoRoot, ".security-mcp", "scans");
  let latest: StoredScan | null = null;
  let latestMtime = 0;
  try {
    const entries = await readdir(dir);
    for (const e of entries) {
      const full = join(dir, e);
      const s = await stat(full);
      if (!s.isFile()) continue;
      if (s.mtimeMs > latestMtime) {
        try {
          latest = JSON.parse(await readFile(full, "utf8")) as StoredScan;
          latestMtime = s.mtimeMs;
        } catch {
          // skip
        }
      }
    }
  } catch {
    // dir doesn't exist yet
  }
  return latest?.findings ?? [];
}
