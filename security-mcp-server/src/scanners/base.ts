import { execa, type ExecaError } from "execa";
import type { Logger } from "pino";
import type { Config } from "../config.js";
import { which } from "../util/shell.js";
import { withTimeout } from "../util/time.js";
import {
  type SecurityFinding,
  type ScannerId,
  type Severity,
  type Level,
  fingerprint as makeFingerprint,
  severityFromCvss,
  severityFromSemgrep,
  severityFromTrivy,
  maskSecret,
} from "../findings.js";
import { ScannerTimeoutError, ToolUnavailableError } from "../errors.js";

export interface ScanContext {
  /** Repo root. */
  root: string;
  /** Optional file/dir target inside the repo. */
  target?: string;
  /** Optional list of Semgrep rule packs to include. */
  includeRuleSets?: string[];
  /** Optional extra Semgrep YAML rule fragments. */
  extraRules?: string[];
  config: Config;
  logger: Logger;
}

export interface RawScanResult {
  /** Scanner id. */
  scanner: ScannerId;
  /** Scanner version (if discoverable). */
  version?: string;
  /** Exit code. */
  exitCode: number;
  /** Raw stdout (parsed into JSON by parsers). */
  stdout: string;
  /** Stderr excerpt (truncated). */
  stderrExcerpt?: string;
  /** Wall-clock duration in ms. */
  durationMs: number;
}

export interface ScannerAdapter {
  id: ScannerId;
  displayName: string;
  binaryPath(envOverride?: string): string;
  isAvailable(): Promise<{ ok: boolean; version?: string; reason?: string }>;
  run(ctx: ScanContext): Promise<RawScanResult>;
  parse(raw: RawScanResult): SecurityFinding[];
}

/**
 * Run a child process safely. Always uses array args (no shell). On Windows,
 * the `taskkill` cleanup path kills the process tree on timeout.
 */
export async function runBinary(
  bin: string,
  args: string[],
  options: {
    cwd: string;
    timeoutMs: number;
    input?: string | null;
    env?: NodeJS.ProcessEnv;
  },
  logger: Logger,
  label: string,
): Promise<RawScanResult> {
  const start = Date.now();
  try {
    const child = execa(bin, args, {
      cwd: options.cwd,
      timeout: options.timeoutMs,
      reject: false,
      input: options.input ?? null,
      env: options.env ?? process.env,
      maxBuffer: 256 * 1024 * 1024,
      stdio: ["pipe", "pipe", "pipe"],
      // shell: false is the default; left explicit for clarity.
      shell: false,
      windowsHide: true,
    });
    const res = await withTimeout(child, options.timeoutMs + 5_000, label);
    return {
      scanner: label as ScannerId,
      exitCode: res.exitCode ?? -1,
      stdout: typeof res.stdout === "string" ? res.stdout : "",
      stderrExcerpt: (res.stderr ?? "").toString().slice(0, 4_000),
      durationMs: Date.now() - start,
    };
  } catch (err) {
    const execaErr = err as ExecaError;
    if ((execaErr.timedOut ?? false) || /timeout after/i.test(String(err))) {
      throw new ScannerTimeoutError(label, options.timeoutMs);
    }
    logger.warn({ bin, args, err: String(err) }, "scanner run failed");
    return {
      scanner: label as ScannerId,
      exitCode: -1,
      stdout: "",
      stderrExcerpt: String(err).slice(0, 4_000),
      durationMs: Date.now() - start,
    };
  }
}

/** Helper: check that a binary is on PATH (or resolved via env override). */
export async function checkAvailable(
  bin: string,
  logger: Logger,
): Promise<{ ok: boolean; version?: string; reason?: string }> {
  const found = await which(bin);
  if (!found) {
    return { ok: false, reason: `binary '${bin}' not found on PATH` };
  }
  try {
    const res = await execa(found, ["--version"], { reject: false, timeout: 5_000 });
    const stdout = typeof res.stdout === "string" ? res.stdout : "";
    const stderr = typeof res.stderr === "string" ? res.stderr : "";
    const version = (stdout || stderr).split(/\r?\n/)[0]?.trim();
    return { ok: true, version };
  } catch (err) {
    logger.warn({ bin, err: String(err) }, "could not determine version");
    return { ok: true, reason: "version probe failed; binary exists" };
  }
}

// ---- Per-scanner finding builders ----------------------------------------

/** Build a `SecurityFinding` from a Semgrep result row. */
export function buildFromSemgrep(
  r: Record<string, unknown>,
  scannerVersion?: string,
  relPath = "",
): SecurityFinding {
  const start = (r.start as Record<string, number> | undefined) ?? { line: 0, col: 0 };
  const end = (r.end as Record<string, number> | undefined) ?? { line: 0, col: 0 };
  const extra = (r.extra as Record<string, unknown> | undefined) ?? {};
  const meta = (extra.metadata as Record<string, unknown> | undefined) ?? {};
  const cwe = normaliseStringArray(meta.cwe);
  const owasp = normaliseStringArray(meta.owasp);
  const references = normaliseStringArray(meta.references);
  const message = String(extra.message ?? r.check_id ?? "");
  const ruleId = String(r.check_id ?? "unknown");
  const severity = severityFromSemgrep(String(extra.severity ?? ""));
  const level: Level = severity === "high" || severity === "critical" ? "error" : "warning";

  const fixRegex = (extra.fix_regex as Record<string, string> | undefined) ?? undefined;
  const fixDiff = (extra.fix as string | undefined) ?? undefined;
  const fixDescription = String(extra.fix_description ?? "");

  const finding: SecurityFinding = {
    id: makeFingerprint({ ruleId, path: relPath, startLine: start.line ?? 0, message }),
    ruleId,
    level,
    severity,
    message,
    location: {
      path: relPath,
      startLine: start.line ?? 0,
      endLine: end.line ?? start.line ?? 0,
      startColumn: start.col,
      endColumn: end.col,
    },
    cwe,
    owasp,
    category: "sast",
    tool: { name: "semgrep", version: scannerVersion },
    fingerprint: makeFingerprint({ ruleId, path: relPath, startLine: start.line ?? 0, message }),
    raw: r,
  };
  if (references.length > 0) finding.references = references;
  if (fixDiff) {
    finding.fix = { description: fixDescription || "Semgrep-provided fix", diff: fixDiff };
  } else if (fixRegex && fixRegex.regex && fixRegex.replacement) {
    finding.fix = {
      description: "Semgrep-provided regex fix",
      diff: `// apply regex: ${fixRegex.regex} -> ${fixRegex.replacement}`,
    };
  }
  return finding;
}

export function buildFromGitleaks(
  r: Record<string, unknown>,
  scannerVersion?: string,
  relPath = "",
): SecurityFinding {
  const ruleId = String(r.RuleID ?? "unknown");
  const startLine = Number(r.StartLine ?? r.Line ?? 0);
  const endLine = Number(r.EndLine ?? r.Line ?? startLine);
  // Build the display message from Gitleaks' `Description` field when
  // available; otherwise fall back to a generic label. The actual secret
  // value is never included — only the masked fingerprint.
  const description = String(r.Description ?? "").trim();
  const masked = maskSecret(String(r.Secret ?? ""));
  const header = description
    ? `Possible secret leak (${ruleId}): ${description}`
    : `Possible secret leak (${ruleId})`;
  const message = masked ? `${header} — matched: ${masked}` : header;
  const severity = severityFromGitleaksRule(ruleId);
  const level: Level = "error";
  // Defensive copy of `r` with `Secret` removed — the raw payload must
  // never carry the secret value back to the model.
  const safeRaw: Record<string, unknown> = { ...r };
  delete safeRaw.Secret;
  delete safeRaw.Match;
  const finding: SecurityFinding = {
    id: makeFingerprint({ ruleId, path: relPath, startLine, message }),
    ruleId,
    level,
    severity,
    message,
    location: {
      path: relPath,
      startLine,
      endLine,
    },
    cwe: ["CWE-798"],
    owasp: ["A07:2021 - Identification and Authentication Failures"],
    category: "secret",
    tool: { name: "gitleaks", version: scannerVersion },
    fix: {
      description: gitleaksFixDescription(ruleId),
      diff: "",
    },
    fingerprint: makeFingerprint({ ruleId, path: relPath, startLine, message }),
    raw: safeRaw,
  };
  return finding;
}

/**
 * Map a Gitleaks rule id to a `Severity`. Secret leaks are always
 * `high` or `critical` per the spec — never lower. The split is by
 * rule-id substring (case-insensitive): known high-impact credentials
 * (private keys, cloud root keys, SCM tokens) are `critical`; the rest
 * are `high`.
 */
function severityFromGitleaksRule(ruleId: string): Severity {
  const id = ruleId.toLowerCase();
  const criticalSubstrings = [
    "private-key",
    "rsa-private",
    "ssh-private",
    "pgp-private",
    "ec-private",
    "openssh",
    "aws-access-token",
    "aws-secret",
    "gcp-service-account",
    "gcp-api-key",
    "azure-shared-key",
    "github-token",
    "github-fine-grained",
    "github-classic",
    "github-app",
    "slack-token",
    "slack-webhook",
    "stripe-secret",
    "sendgrid",
    "mailgun",
    "twilio",
    "npm-token",
    "pypi-token",
    "heroku-api-key",
    "digitalocean-pat",
    "vault-token",
    "kubernetes-secret",
  ];
  return criticalSubstrings.some((s) => id.includes(s)) ? "critical" : "high";
}

/**
 * Build the `fix.description` for a Gitleaks finding. Two calls to action:
 *   1. **Rotate the secret immediately** — assume the leaked value is
 *      compromised (it's been in version control).
 *   2. **Move the value into a secret manager** — Vault / AWS Secrets
 *      Manager / GCP Secret Manager / Azure Key Vault, then read it at
 *      runtime via a SDK or env injection at deploy time.
 *
 * The list is generic enough to cover any provider; the rule id is
 * interpolated so the recommendation is concrete.
 */
function gitleaksFixDescription(ruleId: string): string {
  return [
    `Rule '${ruleId}' matched: the secret is now in version control and must be considered compromised.`,
    "1) Rotate / revoke the credential at the provider IMMEDIATELY (this is the urgent step).",
    "2) Purge the value from git history (git filter-repo / BFG) and force-push; coordinate with reviewers.",
    "3) Migrate the value into a secret manager (HashiCorp Vault, AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, Doppler, or 1Password Secrets Automation) and read it at runtime via the provider's SDK or an env var injected at deploy time — never commit secrets again.",
    "4) Add a pre-commit hook (gitleaks/gitleaks-action or pre-commit/gitleaks) and a CI step (gitleaks-action) to block future leaks.",
  ].join(" ");
}

export function buildFromTrivyVuln(
  v: Record<string, unknown>,
  target: string,
  scannerVersion?: string,
): SecurityFinding {
  const cve = String(v.VulnerabilityID ?? "UNKNOWN");
  const pkg = String(v.PkgName ?? "");
  const installed = String(v.InstalledVersion ?? "");
  const fixed = String(v.FixedVersion ?? "");
  const title = String(v.Title ?? v.Description ?? "Vulnerability");
  const severity = severityFromTrivy(String(v.Severity ?? ""));
  const cvss = (v.CVSS as Record<string, unknown> | undefined) ?? null;
  const nvdScore = cvss?.nvd ? Number((cvss.nvd as Record<string, number>).V3Score ?? NaN) : NaN;
  const severityFromScore = severityFromCvss(Number.isFinite(nvdScore) ? nvdScore : null);
  const finalSeverity: Severity = severity === "info" ? severityFromScore : severity;
  const cweIds = normaliseStringArray(v.CweIDs);
  // Default to CWE-1395 (Dependency on Vulnerable Component) when Trivy
  // doesn't ship its own mapping — keeps the cwe array non-empty for
  // compliance / dashboard consumers.
  const cwe = cweIds.length > 0 ? cweIds : ["CWE-1395"];
  const references = normaliseStringArray(v.References);
  const message = `${cve} in ${pkg}@${installed}${fixed ? ` (fixed in ${fixed})` : ""}: ${title}`;
  const finding: SecurityFinding = {
    id: makeFingerprint({ ruleId: cve, path: target, startLine: 0, message }),
    ruleId: cve,
    level: finalSeverity === "critical" || finalSeverity === "high" ? "error" : "warning",
    severity: finalSeverity,
    message,
    location: { path: target, startLine: 0, endLine: 0 },
    cwe,
    category: "dependency",
    tool: { name: "trivy", version: scannerVersion },
    fingerprint: makeFingerprint({ ruleId: cve, path: target, startLine: 0, message }),
    raw: v,
  };
  if (cve !== "UNKNOWN") finding.cve = [cve];
  if (references.length > 0) finding.references = references;
  return finding;
}

/**
 * Build a `SecurityFinding` from a Trivy `Misconfigurations[]` row. The
 * result target is the file Trivy scanned (Dockerfile, k8s manifest, IaC
 * file, etc.). Category is `container` for k8s/Dockerfile rules and
 * `config` for everything else (the spec lumps IaC + container together
 * into `container`; we keep `config` for non-container IaC so reports
 * can group them differently).
 */
export function buildFromTrivyMisconfig(
  m: Record<string, unknown>,
  target: string,
  scannerVersion?: string,
): SecurityFinding {
  const ruleId = String(m.ID ?? m.AVDID ?? "unknown-misconfig");
  const title = String(m.Title ?? "Misconfiguration");
  const description = String(m.Description ?? "");
  const severity = severityFromTrivy(String(m.Severity ?? "MEDIUM"));
  const message = `${ruleId}: ${title}${description ? ` — ${description.slice(0, 200)}` : ""}`;
  const references = normaliseStringArray(m.References);
  const resolver = String(m.Resolver ?? "");
  const isContainer = /dockerfile|kubernetes|k8s|helm|container/i.test(`${resolver} ${ruleId} ${title}`);
  const causeMeta = (m.CauseMetadata as Record<string, unknown> | undefined) ?? {};
  const startLine = Number(causeMeta.StartLine ?? 0);
  const endLine = Number(causeMeta.EndLine ?? startLine);
  const finding: SecurityFinding = {
    id: makeFingerprint({ ruleId, path: target, startLine, message }),
    ruleId,
    level: severity === "critical" || severity === "high" ? "error" : "warning",
    severity,
    message,
    location: { path: target, startLine, endLine },
    cwe: [],
    category: isContainer ? "container" : "config",
    tool: { name: "trivy", version: scannerVersion },
    fingerprint: makeFingerprint({ ruleId, path: target, startLine, message }),
    raw: m,
  };
  if (references.length > 0) finding.references = references;
  return finding;
}

/**
 * Build a `SecurityFinding` from a Trivy `Secrets[]` row. The secret
 * value is masked in the message and stripped from the raw payload,
 * matching the Gitleaks behaviour (re-use `maskSecret`).
 */
export function buildFromTrivySecret(
  s: Record<string, unknown>,
  target: string,
  scannerVersion?: string,
): SecurityFinding {
  const ruleId = String(s.RuleID ?? "trivy-secret");
  const title = String(s.Title ?? "Secret detected");
  const startLine = Number(s.StartLine ?? 0);
  const endLine = Number(s.EndLine ?? startLine);
  const matched = String(s.Match ?? "");
  const masked = maskSecret(matched);
  const message = masked ? `Possible secret leak (${ruleId}): ${title} — matched: ${masked}` : `Possible secret leak (${ruleId}): ${title}`;
  const safeRaw: Record<string, unknown> = { ...s };
  delete safeRaw.Secret;
  delete safeRaw.Match;
  const finding: SecurityFinding = {
    id: makeFingerprint({ ruleId, path: target, startLine, message }),
    ruleId,
    level: "error",
    severity: "high",
    message,
    location: { path: target, startLine, endLine },
    cwe: ["CWE-798"],
    owasp: ["A07:2021 - Identification and Authentication Failures"],
    category: "secret",
    tool: { name: "trivy", version: scannerVersion },
    fingerprint: makeFingerprint({ ruleId, path: target, startLine, message }),
    raw: safeRaw,
  };
  return finding;
}

/**
 * Build a `SecurityFinding` from a Trivy `Licenses[]` row. License
 * findings are by default `low` / `info` and use the `config` category.
 */
export function buildFromTrivyLicense(
  l: Record<string, unknown>,
  target: string,
  scannerVersion?: string,
): SecurityFinding {
  const name = String(l.Name ?? "UNKNOWN-LICENSE");
  const category = String(l.Category ?? "unknown");
  const severity = severityFromTrivy(String(l.Severity ?? "LOW"));
  const pkg = String(l.PkgName ?? "");
  const message = `License ${name} (${category})${pkg ? ` for ${pkg}` : ""} in ${target}`;
  const references = normaliseStringArray(l.Links);
  const finding: SecurityFinding = {
    id: makeFingerprint({ ruleId: `license-${name}`, path: target, startLine: 0, message }),
    ruleId: `license-${name}`,
    level: severity === "critical" || severity === "high" ? "error" : "warning",
    severity,
    message,
    location: { path: target, startLine: 0, endLine: 0 },
    cwe: [],
    category: "config",
    tool: { name: "trivy", version: scannerVersion },
    fingerprint: makeFingerprint({ ruleId: `license-${name}`, path: target, startLine: 0, message }),
    raw: l,
  };
  if (references.length > 0) finding.references = references;
  return finding;
}

function normaliseStringArray(v: unknown): string[] {
  if (!v) return [];
  if (Array.isArray(v)) return v.filter((x) => typeof x === "string").map(String);
  if (typeof v === "string") return v.split(/[,\s]+/).filter(Boolean);
  return [];
}

export { ToolUnavailableError };
