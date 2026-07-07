import { sha256Hex } from "../utils/file-utils.js";
import {
  type Severity,
  type Level,
  type Category,
  severityToLevel,
  type severityFromCvss as _SeverityFromCvss,
} from "./severity.js";
import { maskSecret } from "../security/redaction.js";

/** Re-export Severity / Level / Category for convenience. */
export type { Severity, Level, Category };

/** Where the finding was detected. */
export interface FindingLocation {
  path: string;
  startLine: number;
  endLine: number;
  startColumn?: number;
  endColumn?: number;
}

/** Proposed fix (unified diff, may be empty for manual review). */
export interface FindingFix {
  description: string;
  diff: string;
}

/** Tool identifier — one of the three scanners. */
export type ScannerId = "semgrep" | "gitleaks" | "trivy";

/** Normalized, SARIF-shaped security finding. */
export interface SecurityFinding {
  id: string;
  ruleId: string;
  level: Level;
  severity: Severity;
  message: string;
  location: FindingLocation;
  cwe: string[];
  cve?: string[];
  owasp?: string[];
  category: Category;
  tool: { name: ScannerId; version?: string };
  fix?: FindingFix;
  /** Stable 16-char fingerprint used for dedup & verification. */
  fingerprint: string;
  /** Original tool payload — omitted from reports. */
  raw?: unknown;
}

/** Compute a stable fingerprint from rule + location + message. */
export function fingerprint(parts: {
  ruleId: string;
  path: string;
  startLine: number;
  message: string;
}): string {
  const key = [parts.ruleId, parts.path, parts.startLine, parts.message].join("|");
  return sha256Hex(key).slice(0, 16);
}

/** Builder helper used by per-scanner normalizers. */
export interface FindingBuilder {
  id?: string;
  ruleId: string;
  severity: Severity;
  message: string;
  location: FindingLocation;
  cwe?: string[];
  cve?: string[];
  owasp?: string[];
  category: Category;
  tool: { name: ScannerId; version?: string };
  fix?: FindingFix;
  raw?: unknown;
}

export function buildFinding(b: FindingBuilder): SecurityFinding {
  const id = b.id ?? fingerprint({
    ruleId: b.ruleId,
    path: b.location.path,
    startLine: b.location.startLine,
    message: b.message,
  });
  // Apply secret masking to messages from secret scanners.
  const message = b.category === "secret" ? maskMessage(b.message) : b.message;
  const f: SecurityFinding = {
    id,
    ruleId: b.ruleId,
    level: severityToLevel(b.severity),
    severity: b.severity,
    message,
    location: b.location,
    cwe: b.cwe ?? [],
    category: b.category,
    tool: b.tool,
    fingerprint: id,
  };
  if (b.cve && b.cve.length > 0) f.cve = b.cve;
  if (b.owasp && b.owasp.length > 0) f.owasp = b.owasp;
  if (b.fix) f.fix = b.fix;
  if (b.raw !== undefined) f.raw = b.raw;
  return f;
}

/** For secret-category findings, ensure the message never embeds the raw secret. */
function maskMessage(msg: string): string {
  // Heuristic: if a long uppercase / hex run is present, mask it.
  return msg.replace(/[A-Za-z0-9_\-+/=]{16,}/g, (m) => maskSecret(m));
}
