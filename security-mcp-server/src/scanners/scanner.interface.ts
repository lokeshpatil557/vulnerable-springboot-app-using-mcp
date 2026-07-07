import type { SecurityFinding, ScannerId } from "../core/finding.js";
import type { ScanContext } from "../core/scan-context.js";

/** Availability probe result. */
export interface AvailabilityResult {
  ok: boolean;
  version?: string;
  reason?: string;
}

/**
 * Scanner adapter contract. Every concrete scanner (semgrep, gitleaks,
 * trivy) implements this. The orchestrator calls `isAvailable()` first,
 * then `scan()` to actually run the tool.
 *
 * Implementations must:
 *   - Use `utils/exec.ts` for child-process execution (no shell).
 *   - Honour `ctx.config.scanTimeoutMs`.
 *   - Never write outside the repo.
 *   - Return normalized `SecurityFinding[]` (call `buildFinding` in
 *     `core/finding.ts`).
 */
export interface ScannerAdapter {
  readonly id: ScannerId;
  readonly displayName: string;
  /** Path to the binary, or name resolved on PATH. */
  binaryPath(): string;
  /** Probe whether the binary is installed and the configured version. */
  isAvailable(): Promise<AvailabilityResult>;
  /** Run the scanner against `ctx` and return parsed findings. */
  scan(ctx: ScanContext): Promise<SecurityFinding[]>;
}
