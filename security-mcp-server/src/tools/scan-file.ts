import type { ToolContext, AnyMcpServer } from "./_shared.js";
import { z, auditWrap, ok } from "./_shared.js";
import { runScanners } from "../scanners/registry.js";
import { assertInsideRepo } from "../paths.js";

export function register(server: AnyMcpServer, ctx: ToolContext): void {
  server.tool(
    "scan_file",
    "Scan a single file inside the repository. Dispatches by extension: " +
      "config/secret-bearing files (e.g. .env, .yml, .json) go to gitleaks; lockfiles/manifests go to trivy fs; " +
      "source files go to semgrep. The file must be inside the repo root.",
    {
      file: z.string().min(1).max(4096),
      scanners: z.array(z.enum(["semgrep", "gitleaks", "trivy"])).optional(),
    },
    async (args) =>
      auditWrap(ctx, "scan_file", args, async () => {
        const a = args as { file: string; scanners?: Array<"semgrep" | "gitleaks" | "trivy"> };
        // Ensure the file is inside the repo root.
        const abs = assertInsideRepo(ctx.repoRoot, a.file);
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
