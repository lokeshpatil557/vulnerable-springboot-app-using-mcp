import type { ToolContext, AnyMcpServer } from "./_shared.js";
import { z, auditWrap, ok } from "./_shared.js";
import { runScanners } from "../scanners/registry.js";
import { guardReadPathAsync, policyFromConfig } from "../security/path-safety.js";

export function register(server: AnyMcpServer, ctx: ToolContext): void {
  server.tool(
    "scan_file",
    "Scan a single file inside the repository. Dispatches by extension: " +
      "config/secret-bearing files (e.g. .env, .yml, .json) go to gitleaks; lockfiles/manifests go to trivy fs; " +
      "source files go to semgrep. The file must be inside the repo root and pass all path-safety checks.",
    {
      file: z.string().min(1).max(4096),
      scanners: z.array(z.enum(["semgrep", "gitleaks", "trivy"])).optional(),
    },
    async (args) =>
      auditWrap(ctx, "scan_file", args, async () => {
        const a = args as { file: string; scanners?: Array<"semgrep" | "gitleaks" | "trivy"> };
        const policy = policyFromConfig(ctx.config.pathSafety, ctx.repoRoot);
        // Enforce 1 (allowed root), 2 (no traversal), 3 (no symlink escape),
        // 4 (no home/root), 6 (file size cap). 5 (binary) and 7 (repo size)
        // are skipped here — scan_file is a read-only scan, not a
        // remediation flow, and binary dispatch is handled by extension.
        const guarded = await guardReadPathAsync(ctx.repoRoot, a.file, policy, {
          tool: "scan_file",
        });
        const abs = guarded.absPath;
        const ext = abs.toLowerCase();
        const isSource = /\.(java|kt|scala|groovy|js|ts|jsx|tsx|py|go|rb|php|cs|cpp|c|h|rs)$/.test(ext);
        const isLock = /(package-lock|yarn\.lock|pom\.xml|build\.gradle|requirements.*\.txt|go\.sum|composer\.lock|gemfile\.lock|packages\.lock\.json)/.test(
          abs.toLowerCase(),
        );
        const defaultScanners: Array<"semgrep" | "gitleaks" | "trivy"> = isLock
          ? ["trivy"]
          : isSource
            ? ["semgrep"]
            : ["gitleaks"];
        const ids = a.scanners && a.scanners.length > 0 ? a.scanners : defaultScanners;
        const { findings, unavailable, durationMs, perScanner } = await runScanners(
          {
            root: ctx.repoRoot,
            target: a.file,
            config: ctx.config,
            logger: ctx.logger,
          },
          ctx.scanners,
          { ids },
          ctx.logger,
        );
        return ok({ findings, unavailable, durationMs, perScanner });
      }),
  );
}
