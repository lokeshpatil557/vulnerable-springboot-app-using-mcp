import pLimit from "p-limit";
import type { Logger } from "pino";
import { type ScanContext } from "./scan-context.js";
import type { SecurityFinding, ScannerId } from "./finding.js";
import { type ScannerAdapter } from "../scanners/scanner.interface.js";

export interface UnavailableScanner {
  tool: string;
  reason: string;
}

export interface OrchestratorOptions {
  /** Restrict to these scanner ids. Default: all enabled. */
  ids?: ScannerId[];
}

export interface OrchestratorResult {
  findings: SecurityFinding[];
  unavailable: UnavailableScanner[];
  perScanner: { id: string; findings: number; durationMs: number }[];
  durationMs: number;
}

/**
 * Run every available scanner in parallel, with graceful degradation.
 *   1. Probe availability of each scanner; record the reason if missing.
 *   2. Run the available ones under `p-limit(MAX_CONCURRENT_SCANNERS)`.
 *   3. Use `Promise.allSettled` so one crash never poisons the rest.
 */
export async function runOrchestrator(
  ctx: ScanContext,
  scanners: readonly ScannerAdapter[],
  options: OrchestratorOptions = {},
  logger: Logger,
): Promise<OrchestratorResult> {
  const selected: ScannerAdapter[] = options.ids
    ? scanners.filter((s) => options.ids!.includes(s.id))
    : [...scanners];

  // Probe availability.
  const probed: { adapter: ScannerAdapter; unavailable?: UnavailableScanner }[] = [];
  for (const adapter of selected) {
    try {
      const r = await adapter.isAvailable();
      if (!r.ok) {
        probed.push({ adapter, unavailable: { tool: adapter.id, reason: r.reason ?? "not available" } });
      } else {
        probed.push({ adapter });
      }
    } catch (err) {
      probed.push({ adapter, unavailable: { tool: adapter.id, reason: (err as Error).message } });
    }
  }

  const limit = pLimit(ctx.config.maxConcurrentScanners);
  const startedAt = Date.now();
  const tasks = probed
    .filter((p) => !p.unavailable)
    .map((p) =>
      limit(async (): Promise<{ id: string; findings: SecurityFinding[]; durationMs: number }> => {
        const start = Date.now();
        try {
          const findings = await p.adapter.scan(ctx);
          return { id: p.adapter.id, findings, durationMs: Date.now() - start };
        } catch (err) {
          logger.warn({ scanner: p.adapter.id, err: String(err) }, "scanner failed");
          return { id: p.adapter.id, findings: [], durationMs: Date.now() - start };
        }
      }),
    );

  const settled = await Promise.allSettled(tasks);
  const findings: SecurityFinding[] = [];
  const perScanner: { id: string; findings: number; durationMs: number }[] = [];
  for (const s of settled) {
    if (s.status === "fulfilled" && s.value) {
      findings.push(...s.value.findings);
      perScanner.push({
        id: s.value.id,
        findings: s.value.findings.length,
        durationMs: s.value.durationMs,
      });
    }
  }

  return {
    findings,
    unavailable: probed.filter((p) => p.unavailable).map((p) => p.unavailable!),
    perScanner,
    durationMs: Date.now() - startedAt,
  };
}
