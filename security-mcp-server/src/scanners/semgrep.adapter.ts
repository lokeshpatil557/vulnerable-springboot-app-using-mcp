import { buildFinding, type FindingBuilder, type SecurityFinding } from "../core/finding.js";
import { severityFromSemgrep } from "../core/severity.js";
import { sandboxForRepo } from "../security/sandbox.js";
import { exec, type ExecResult } from "../utils/exec.js";

export interface SemgrepResultRow {
  check_id: string;
  path: string;
  start: { line: number; col: number };
  end: { line: number; col: number };
  extra?: {
    message?: string;
    severity?: string;
    metadata?: {
      cwe?: string | string[];
      owasp?: string | string[];
      references?: string[];
    };
    fix?: string;
    fix_description?: string;
    fix_regex?: { regex: string; replacement: string };
  };
}

interface SemgrepOutput {
  results?: SemgrepResultRow[];
  errors?: unknown[];
  version?: string;
}

export class SemgrepAdapter {
  readonly id = "semgrep" as const;
  readonly displayName = "Semgrep (SAST)";
  private cachedVersion: string | undefined;

  constructor(private readonly binOverride?: string) {}

  binaryPath(): string {
    return this.binOverride ?? "semgrep";
  }

  async isAvailable(): Promise<{ ok: boolean; version?: string; reason?: string }> {
    const bin = this.binaryPath();
    const r = await exec(bin, ["--version"], { timeoutMs: 5_000 });
    if (r.exitCode !== 0) {
      return { ok: false, reason: `binary '${bin}' not available (exit ${r.exitCode})` };
    }
    this.cachedVersion = r.stdout.split(/\r?\n/)[0]?.trim();
    return { ok: true, version: this.cachedVersion };
  }

  async scan(ctx: import("../core/scan-context.js").ScanContext): Promise<SecurityFinding[]> {
    const bin = this.binaryPath();
    const args: string[] = ["scan", "--json", "--quiet", "--error", "--no-git-ignore"];
    for (const r of ctx.includeRuleSets) args.push("--config", r);
    for (const r of ctx.extraRules) args.push("--config", r);
    args.push("--", ctx.target ?? ".");
    const sb = sandboxForRepo(ctx.repoRoot);
    const res: ExecResult = await exec(bin, args, {
      cwd: sb.cwd,
      env: sb.env,
      timeoutMs: ctx.config.scanTimeoutMs,
    });
    if (res.timedOut) {
      throw new Error(`semgrep timed out after ${ctx.config.scanTimeoutMs}ms`);
    }
    return parseSemgrepOutput(res.stdout, this.cachedVersion);
  }
}

/** Parse Semgrep JSON output and return normalized findings. */
export function parseSemgrepOutput(stdout: string, version?: string): SecurityFinding[] {
  if (!stdout) return [];
  let parsed: SemgrepOutput;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    return [];
  }
  if (!Array.isArray(parsed.results)) return [];
  return parsed.results.map((r) => buildFindingFromSemgrep(r, version));
}

export function buildFindingFromSemgrep(row: SemgrepResultRow, version?: string): SecurityFinding {
  const meta = row.extra?.metadata ?? {};
  const cwe = normaliseStringArray(meta.cwe);
  const owasp = normaliseStringArray(meta.owasp);
  const ruleId = row.check_id ?? "unknown";
  const message = row.extra?.message ?? ruleId;
  const severity = severityFromSemgrep(row.extra?.severity);
  const builder: FindingBuilder = {
    ruleId,
    severity,
    message,
    location: {
      path: row.path,
      startLine: row.start.line,
      endLine: row.end.line,
      startColumn: row.start.col,
      endColumn: row.end.col,
    },
    cwe,
    owasp,
    category: "sast",
    tool: { name: "semgrep", version },
    raw: row,
  };
  if (row.extra?.fix) {
    builder.fix = {
      description: row.extra.fix_description ?? "Semgrep-provided fix",
      diff: row.extra.fix,
    };
  } else if (row.extra?.fix_regex) {
    builder.fix = {
      description: "Semgrep-provided regex fix",
      diff: `// apply regex: ${row.extra.fix_regex.regex} -> ${row.extra.fix_regex.replacement}`,
    };
  }
  return buildFinding(builder);
}

function normaliseStringArray(v: unknown): string[] {
  if (!v) return [];
  if (Array.isArray(v)) return v.filter((x) => typeof x === "string").map(String);
  if (typeof v === "string") return v.split(/[,\s]+/).filter(Boolean);
  return [];
}
