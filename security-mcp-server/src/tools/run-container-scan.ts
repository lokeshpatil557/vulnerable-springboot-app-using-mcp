import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { ToolContext, AnyMcpServer } from "./_shared.js";
import { z, auditWrap, ok } from "./_shared.js";
import { runScanners } from "../scanners/registry.js";
import { NoImageFoundError } from "../errors.js";

export function register(server: AnyMcpServer, ctx: ToolContext): void {
  server.tool(
    "run_container_scan",
    "Scan a container image. The image can be supplied via the `image` arg, " +
      "inferred from a Dockerfile `FROM` line, or pulled from a docker-compose service. " +
      "Returns an error if no image can be resolved.",
    {
      image: z.string().min(1).max(512).optional(),
    },
    async (args) =>
      auditWrap(ctx, "run_container_scan", args, async () => {
        const a = args as { image?: string };
        const image = a.image ?? (await resolveImageFromRepo(ctx.repoRoot));
        if (!image) {
          throw new NoImageFoundError(ctx.repoRoot);
        }
        const { findings, unavailable, durationMs, perScanner } = await runScanners(
          {
            root: ctx.repoRoot,
            config: ctx.config,
            logger: ctx.logger,
          },
          ctx.scanners,
          { ids: ["trivy"], trivyMode: "image", trivyImage: image },
          ctx.logger,
        );
        return ok({ image, findings, unavailable, durationMs, perScanner });
      }),
  );
}

async function resolveImageFromRepo(repoRoot: string): Promise<string | null> {
  // Try Dockerfile first.
  try {
    const text = await readFile(join(repoRoot, "Dockerfile"), "utf8");
    const m = text.match(/^FROM\s+([^\s]+)/im);
    if (m) return m[1]!;
  } catch {
    // ignore
  }
  // Try docker-compose*.yml.
  for (const name of ["docker-compose.yml", "docker-compose.yaml", "compose.yaml"]) {
    try {
      const text = await readFile(join(repoRoot, name), "utf8");
      const m = text.match(/^\s{2}([a-zA-Z0-9_-]+):\s*$/m);
      if (!m) continue;
      // Best-effort: find an `image:` key under that service block.
      const svcName = m[1]!;
      const blockRe = new RegExp(`^\\s{2}${svcName}:\\s*$([\\s\\S]*?)(?=^\\s{2}\\w|^\\Z)`, "m");
      const blockMatch = blockRe.exec(text);
      if (!blockMatch) continue;
      const imgMatch = /image:\s*([^\s#]+)/.exec(blockMatch[1]!);
      if (imgMatch) return imgMatch[1]!;
    } catch {
      // ignore
    }
  }
  return null;
}
