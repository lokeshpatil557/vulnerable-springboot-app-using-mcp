import { z } from "zod";
import type { ToolContext, AnyMcpServer } from "./_shared.js";
import { RunScannersInput as Schema, auditWrap, ok } from "./_shared.js";
import { runScanners } from "../scanners/registry.js";
import { identifyCodebase } from "../stack-detect.js";
import { getAdapters } from "../adapters/registry.js";

type RunScannersInput = z.infer<typeof Schema>;

export function register(server: AnyMcpServer, ctx: ToolContext): void {
  server.tool(
    "detect_vulnerabilities",
    "Run a configurable subset of scanners and incorporate any stack-specific Semgrep rule fragments. " +
      "Equivalent to scan_directory but lets the caller choose which scanners to run and which rule packs to include.",
    Schema.shape,
    async (args) =>
      auditWrap(ctx, "detect_vulnerabilities", args, async () => {
        const input = args as unknown as RunScannersInput;
        // Collect extra rules from any matched adapters.
        const matches = await identifyCodebase(ctx.repoRoot);
        const matchedIds = new Set(matches.filter((m) => m.confidence >= 0.5).map((m) => m.adapterId));
        const extras: string[] = [];
        for (const adapter of getAdapters()) {
          if (matchedIds.has(adapter.id) && adapter.extraRules) {
            for (const r of adapter.extraRules()) extras.push(r.yaml);
          }
        }
        const { findings, unavailable, durationMs, perScanner } = await runScanners(
          {
            root: ctx.repoRoot,
            target: input.target,
            includeRuleSets: input.includeRuleSets ?? ctx.config.includeRuleSets,
            extraRules: extras,
            config: ctx.config,
            logger: ctx.logger,
          },
          ctx.scanners,
          { ids: input.ids },
          ctx.logger,
        );
        return ok({ findings, unavailable, durationMs, perScanner, appliedExtras: extras.length });
      }),
  );
}
