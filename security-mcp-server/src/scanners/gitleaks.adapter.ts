import { buildFinding, type FindingBuilder, type SecurityFinding } from "../core/finding.js";
import { severityFromGitleaks } from "../core/severity.js";
import { sandboxForRepo } from "../security/sandbox.js";
import { exec, type ExecResult } from "../utils/exec.js";
import { join } from "node:path";

export interface GitleaksFindingRaw {
  Description?: string;
  RuleID?: string;
  Match?: string;
  Secret?: string;
  File?: string;
  StartLine?: number;
  EndLine?: number;
  Line?: number;
  Commit?: string;
  Entropy?: number;
  Author?: string;
  Email?: string;
  Date?: string;
  Tags?: string[];
}

export class GitleaksAdapter {
  readonly id = "gitleaks" as const;
  readonly displayName = "Gitleaks (secret detection)";
  private cachedVersion: string | undefined;

  constructor(private readonly binOverride?: string) {}

  binaryPath(): string {
    return this.binOverride ?? "gitleaks";
  }

  async isAvailable(): Promise<{ ok: boolean; version?: string; reason?: string }> {
    const bin = this.binaryPath();
    const r = await exec(bin, ["version"], { timeoutMs: 5_000 });
    if (r.exitCode !== 0) {
      return { ok: false, reason: `binary '${bin}' not available (exit ${r.exitCode})` };
    }
    this.cachedVersion = r.stdout.split(/\r?\n/)[0]?.trim();
    return { ok: true, version: this.cachedVersion };
  }

  async scan(ctx: import("../core/scan-context.js").ScanContext): Promise<SecurityFinding[]> {
    const bin = this.binaryPath();
    const target = ctx.target ?? ctx.repoRoot;
    const args: string[] = [
      "detect",
      "--no-banner",
      "--no-git",
      "--source",
      ctx.repoRoot,
      "--report-format",
      "json",
      "--report-path",
      "-",
      "--exit-code",
      "0",
    ];
    if (ctx.target && ctx.target !== ctx.repoRoot) {
      args.push(join(ctx.repoRoot, ctx.target));
    }
    const sb = sandboxForRepo(ctx.repoRoot);
    const res: ExecResult = await exec(bin, args, {
      cwd: sb.cwd,
      env: sb.env,
      timeoutMs: ctx.config.scanTimeoutMs,
    });
    if (res.timedOut) {
      throw new Error(`gitleaks timed out after ${ctx.config.scanTimeoutMs}ms`);
    }
    // gitleaks exits 1 when leaks are found; that's still success.
    if (res.exitCode !== 0 && res.exitCode !== 1) {
      // Hard error.
      throw new Error(`gitleaks failed (exit ${res.exitCode}): ${res.stderr.slice(0, 500)}`);
    }
    return parseGitleaksOutput(res.stdout, this.cachedVersion);
  }
}

/** Parse Gitleaks JSON output (top-level array). */
export function parseGitleaksOutput(stdout: string, version?: string): SecurityFinding[] {
  if (!stdout) return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    return [];
  }
  if (!Array.isArray(parsed)) return [];
  return (parsed as GitleaksFindingRaw[]).map((r) => buildFindingFromGitleaks(r, version));
}

export function buildFindingFromGitleaks(r: GitleaksFindingRaw, version?: string): SecurityFinding {
  const ruleId = r.RuleID ?? "unknown";
  const startLine = r.StartLine ?? r.Line ?? 0;
  const endLine = r.EndLine ?? r.Line ?? startLine;
  // Gitleaks stores the file path as relative inside the repo.
  const relPath = r.File ?? "";
  const builder: FindingBuilder = {
    ruleId,
    severity: severityFromGitleaks(),
    message: `Possible secret leak (${ruleId})`,
    location: { path: relPath, startLine, endLine },
    cwe: ["CWE-798"],
    owasp: ["A07:2021 - Identification and Authentication Failures"],
    category: "secret",
    tool: { name: "gitleaks", version },
    raw: r,
  };
  return buildFinding(builder);
}
