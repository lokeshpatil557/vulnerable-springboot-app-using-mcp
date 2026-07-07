import { mkdir } from "node:fs/promises";
import { dirname, isAbsolute, join } from "node:path";
import { buildFinding, type FindingBuilder, type SecurityFinding } from "../core/finding.js";
import { severityFromCvss, severityFromTrivy } from "../core/severity.js";
import { sandboxForRepo } from "../security/sandbox.js";
import { exec, type ExecResult } from "../utils/exec.js";

export type TrivyMode = "fs" | "image" | "sbom";

export interface TrivyVulnRaw {
  VulnerabilityID?: string;
  PkgName?: string;
  InstalledVersion?: string;
  FixedVersion?: string;
  Title?: string;
  Description?: string;
  Severity?: string;
  CVSS?: { nvd?: { V3Score?: number } };
  CweIDs?: string[];
  References?: string[];
}

export interface TrivyResultRaw {
  Target?: string;
  Class?: string;
  Type?: string;
  Vulnerabilities?: TrivyVulnRaw[];
}

interface TrivyOutput {
  Results?: TrivyResultRaw[];
}

export class TrivyAdapter {
  readonly id = "trivy" as const;
  readonly displayName = "Trivy (vuln / IaC / container / SBOM)";
  private cachedVersion: string | undefined;
  private mode: TrivyMode = "fs";
  private image: string | undefined;
  private sbomOutPath: string | undefined;

  constructor(private readonly binOverride?: string) {}

  binaryPath(): string {
    return this.binOverride ?? "trivy";
  }

  setOptions(opts: { mode?: TrivyMode; image?: string; sbomOutPath?: string }): void {
    if (opts.mode) this.mode = opts.mode;
    if (opts.image !== undefined) this.image = opts.image;
    if (opts.sbomOutPath !== undefined) this.sbomOutPath = opts.sbomOutPath;
  }

  async isAvailable(): Promise<{ ok: boolean; version?: string; reason?: string }> {
    const bin = this.binaryPath();
    const r = await exec(bin, ["--version"], { timeoutMs: 10_000 });
    if (r.exitCode !== 0) {
      return { ok: false, reason: `binary '${bin}' not available (exit ${r.exitCode})` };
    }
    this.cachedVersion = r.stdout.split(/\r?\n/)[0]?.trim();
    return { ok: true, version: this.cachedVersion };
  }

  async scan(ctx: import("../core/scan-context.js").ScanContext): Promise<SecurityFinding[]> {
    const bin = this.binaryPath();
    const sb = sandboxForRepo(ctx.repoRoot);
    let args: string[];
    switch (this.mode) {
      case "image": {
        if (!this.image) throw new Error("trivy image mode requires 'image' to be set");
        args = ["image", "--format", "json", "--output", "-", this.image];
        break;
      }
      case "sbom": {
        const outPath = this.sbomOutPath
          ? isAbsolute(this.sbomOutPath)
            ? this.sbomOutPath
            : join(ctx.repoRoot, this.sbomOutPath)
          : join(ctx.repoRoot, ".security-mcp", "sbom", "trivy.cdx.json");
        await mkdir(dirname(outPath), { recursive: true });
        args = ["fs", "--format", "cyclonedx", "--output", outPath, "--", ctx.repoRoot];
        break;
      }
      case "fs":
      default:
        args = ["fs", "--format", "json", "--output", "-", "--", ctx.repoRoot];
        break;
    }
    const res: ExecResult = await exec(bin, args, {
      cwd: sb.cwd,
      env: sb.env,
      timeoutMs: ctx.config.scanTimeoutMs,
    });
    if (res.timedOut) {
      throw new Error(`trivy timed out after ${ctx.config.scanTimeoutMs}ms`);
    }
    if (this.mode === "sbom") return []; // sbom mode produces no findings
    return parseTrivyOutput(res.stdout, this.cachedVersion);
  }
}

/** Parse Trivy JSON output and return normalized findings. */
export function parseTrivyOutput(stdout: string, version?: string): SecurityFinding[] {
  if (!stdout) return [];
  let parsed: TrivyOutput;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    return [];
  }
  if (!Array.isArray(parsed.Results)) return [];
  const out: SecurityFinding[] = [];
  for (const r of parsed.Results) {
    const target = r.Target ?? "";
    const vulns = r.Vulnerabilities ?? [];
    for (const v of vulns) {
      out.push(buildFindingFromTrivy(v, target, version));
    }
  }
  return out;
}

export function buildFindingFromTrivy(v: TrivyVulnRaw, target: string, version?: string): SecurityFinding {
  const cve = v.VulnerabilityID ?? "UNKNOWN";
  const pkg = v.PkgName ?? "";
  const installed = v.InstalledVersion ?? "";
  const fixed = v.FixedVersion ?? "";
  const title = v.Title ?? v.Description ?? "Vulnerability";
  const severity = severityFromTrivy(v.Severity);
  const nvdScore = v.CVSS?.nvd?.V3Score;
  const finalSeverity = severity === "info" ? severityFromCvss(nvdScore) : severity;
  const cwe = v.CweIDs ?? [];
  const message = `${cve} in ${pkg}@${installed}${fixed ? ` (fixed in ${fixed})` : ""}: ${title}`;
  const builder: FindingBuilder = {
    ruleId: cve,
    severity: finalSeverity,
    message,
    location: { path: target, startLine: 0, endLine: 0 },
    cwe,
    category: "vuln",
    tool: { name: "trivy", version },
    raw: v,
  };
  if (cve !== "UNKNOWN") builder.cve = [cve];
  return buildFinding(builder);
}
