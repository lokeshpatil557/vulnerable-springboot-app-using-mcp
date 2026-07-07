import pLimit from "p-limit";
import type { Logger } from "pino";
import type { Config } from "../config.js";
import { GitleaksAdapter } from "./gitleaks.js";
import { SemgrepAdapter } from "./semgrep.js";
import { TrivyAdapter, type TrivyMode } from "./trivy.js";
import { type ScannerAdapter, type ScanContext } from "./base.js";
import type { SecurityFinding } from "../findings.js";

export type ScannerId = "semgrep" | "gitleaks" | "trivy";

export interface UnavailableScanner {
  tool: string;
  reason: string;
}

export interface RunScannersOptions {
  /** If provided, restrict to these scanner ids. Default: all. */
  ids?: ScannerId[];
  trivyMode?: TrivyMode;
  trivyImage?: string;
  trivySbomOutPath?: string;
}

export interface PerScannerStat {
  id: string;
  findings: number;
  durationMs: number;
}

export interface RunScannersResult {
  findings: SecurityFinding[];
  unavailable: UnavailableScanner[];
  durationMs: number;
  perScanner: PerScannerStat[];
}

export interface ScannerRegistry {
  semgrep: SemgrepAdapter;
  gitleaks: GitleaksAdapter;
  trivy: TrivyAdapter;
}

export function buildScannerRegistry(config: Config): ScannerRegistry {
  return {
    semgrep: new SemgrepAdapter(config.perScannerBinaries.semgrep),
    gitleaks: new GitleaksAdapter(config.perScannerBinaries.gitleaks),
    trivy: new TrivyAdapter(config.perScannerBinaries.trivy),
  };
}

/**
 * Orchestrate the available scanners in parallel with graceful degradation.
 * Unavailable scanners are recorded in `unavailable[]`; the others still
 * run. One scanner crashing never poisons the rest (`Promise.allSettled`).
 */
export async function runScanners(
  ctx: ScanContext,
  scanners: ScannerRegistry,
  options: RunScannersOptions = {},
  logger: Logger,
): Promise<RunScannersResult> {
  const all: ScannerAdapter[] = [scanners.semgrep, scanners.gitleaks, scanners.trivy];
  const selected: ScannerAdapter[] = options.ids
    ? all.filter((s) => options.ids!.includes(s.id as ScannerId))
    : all;

  if (options.trivyMode) {
    scanners.trivy.setOptions({
      mode: options.trivyMode,
      image: options.trivyImage,
      sbomOutPath: options.trivySbomOutPath,
    });
  }

  // Probe availability first.
  type Probed = { adapter: ScannerAdapter; unavailable?: UnavailableScanner };
  const probed: Probed[] = [];
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
  const started = Date.now();

  const tasks = probed
    .filter((p) => !p.unavailable)
    .map((p) =>
      limit(async (): Promise<{ id: string; findings: SecurityFinding[]; durationMs: number }> => {
        const start = Date.now();
        try {
          const raw = await p.adapter.run(ctx);
          const findings = p.adapter.parse(raw);
          return { id: p.adapter.id, findings, durationMs: Date.now() - start };
        } catch (err) {
          logger.warn({ scanner: p.adapter.id, err: String(err) }, "scanner failed");
          return { id: p.adapter.id, findings: [], durationMs: Date.now() - start };
        }
      }),
    );

  const settled = await Promise.allSettled(tasks);
  const findings: SecurityFinding[] = [];
  const perScanner: PerScannerStat[] = [];
  for (const s of settled) {
    if (s.status === "fulfilled" && s.value) {
      findings.push(...s.value.findings);
      perScanner.push({ id: s.value.id, findings: s.value.findings.length, durationMs: s.value.durationMs });
    }
  }

  return {
    findings,
    unavailable: probed.filter((p) => p.unavailable).map((p) => p.unavailable!),
    durationMs: Date.now() - started,
    perScanner,
  };
}
