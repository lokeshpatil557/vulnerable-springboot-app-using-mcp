/**
 * SARIF 2.1.0 report. Validated against the official schema
 * (https://json.schemastore.org/sarif-2.1.0.json).
 *
 * The output is consumable by:
 *   - GitHub code scanning (via `github/codeql-action/upload-sarif`)
 *   - VS Code's SARIF viewer
 *   - `microsoft/sarif-multitool` (`sarif validate`)
 *   - Any tool that supports SARIF 2.1.0 result ingestion
 *
 * The `properties.security-severity` field uses the GitHub-recommended
 * scale (0.0–10.0) so that PR decorations render with the correct
 * severity icon.
 */
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, join } from "node:path";
import { severityToLevel, type Level } from "../core/severity.js";
import type { SecurityFinding, Severity } from "../findings.js";
import type { ReportMeta } from "./json.js";

/** Map a Severity to GitHub's security-severity scale (0.0–10.0). */
function securitySeverityScore(sev: Severity): number {
  switch (sev) {
    case "critical":
      return 9.5;
    case "high":
      return 7.5;
    case "medium":
      return 5.0;
    case "low":
      return 2.5;
    case "info":
      return 0.1;
  }
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  helpUri?: string;
  defaultConfiguration: { level: Level };
  properties: {
    tags: string[];
    precision: "high" | "medium" | "low";
    "security-severity": string;
  };
}

interface SarifResult {
  ruleId: string;
  ruleIndex: number;
  level: Level;
  message: { text: string };
  locations: Array<{
    physicalLocation: {
      artifactLocation: { uri: string; uriBaseId: string };
      region: {
        startLine: number;
        endLine?: number;
        startColumn?: number;
        endColumn?: number;
      };
    };
  }>;
  partialFingerprints: { primary: string };
  fixes?: Array<{
    description: { text: string };
    artifactChanges: Array<{
      artifactLocation: { uri: string; uriBaseId: string };
      replacements: Array<{
        deletedRegion: { startLine?: number };
        insertedContent: { text: string };
      }>;
    }>;
  }>;
  properties: {
    "security-severity": string;
    category: string;
    cwe: string[];
    cve: string[];
    owasp: string[];
  };
}

export interface SarifReport {
  $schema: "https://json.schemastore.org/sarif-2.1.0.json";
  version: "2.1.0";
  runs: Array<{
    tool: {
      driver: {
        name: string;
        version: string;
        informationUri: string;
        rules: SarifRule[];
      };
    };
    invocations: Array<{
      executionSuccessful: boolean;
      startTimeUtc: string;
      endTimeUtc: string;
    }>;
    originalUriBaseIds: { PROJECTROOT: { uri: string } };
    results: SarifResult[];
  }>;
}

/** Pure renderer — no I/O. */
export function renderSarifReport(
  findings: SecurityFinding[],
  meta: ReportMeta,
): SarifReport {
  // De-duplicate rules by ruleId while preserving first-seen order.
  const ruleIndex = new Map<string, number>();
  const rules: SarifRule[] = [];
  for (const f of findings) {
    if (ruleIndex.has(f.ruleId)) continue;
    ruleIndex.set(f.ruleId, rules.length);
    const level = severityToLevel(f.severity);
    const tags = [
      "security",
      f.category,
      ...(f.cwe ?? []),
      ...(f.cve ?? []),
      ...(f.owasp ?? []),
    ];
    rules.push({
      id: f.ruleId,
      name: f.ruleId,
      shortDescription: { text: f.message.slice(0, 200) },
      fullDescription: { text: f.message },
      ...(f.references?.[0] ? { helpUri: f.references[0] } : {}),
      defaultConfiguration: { level },
      properties: {
        tags,
        precision: "high",
        "security-severity": securitySeverityScore(f.severity).toFixed(1),
      },
    });
  }

  const results: SarifResult[] = findings.map((f) => {
    const result: SarifResult = {
      ruleId: f.ruleId,
      ruleIndex: ruleIndex.get(f.ruleId) ?? 0,
      level: severityToLevel(f.severity),
      message: { text: f.message },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: f.location.path, uriBaseId: "PROJECTROOT" },
            region: {
              startLine: f.location.startLine,
              ...(f.location.endLine && f.location.endLine !== f.location.startLine
                ? { endLine: f.location.endLine }
                : {}),
              ...(f.location.startColumn !== undefined
                ? { startColumn: f.location.startColumn }
                : {}),
              ...(f.location.endColumn !== undefined
                ? { endColumn: f.location.endColumn }
                : {}),
            },
          },
        },
      ],
      partialFingerprints: { primary: f.fingerprint },
      properties: {
        "security-severity": securitySeverityScore(f.severity).toFixed(1),
        category: f.category,
        cwe: f.cwe ?? [],
        cve: f.cve ?? [],
        owasp: f.owasp ?? [],
      },
    };
    if (f.fix && f.fix.diff && f.fix.diff.length > 0) {
      result.fixes = [
        {
          description: { text: f.fix.description || "Suggested fix" },
          artifactChanges: [
            {
              artifactLocation: { uri: f.location.path, uriBaseId: "PROJECTROOT" },
              replacements: [
                {
                  deletedRegion: { startLine: f.location.startLine },
                  insertedContent: { text: f.fix.diff },
                },
              ],
            },
          ],
        },
      ];
    }
    return result;
  });

  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "security-mcp-server",
            version: "0.1.0",
            informationUri:
              "https://github.com/lokeshpatil557/vulnerable-springboot-app-using-mcp",
            rules,
          },
        },
        invocations: [
          {
            executionSuccessful: true,
            startTimeUtc: meta.startedAt,
            endTimeUtc: meta.finishedAt,
          },
        ],
        originalUriBaseIds: {
          PROJECTROOT: { uri: pathToFileUri(meta.repoRoot) },
        },
        results,
      },
    ],
  };
}

export async function writeSarifReport(
  findings: SecurityFinding[],
  destPath: string,
  meta: ReportMeta,
): Promise<string> {
  const doc = renderSarifReport(findings, meta);
  const abs = isAbsolute(destPath) ? destPath : join(meta.repoRoot, destPath);
  await mkdir(dirname(abs), { recursive: true });
  await writeFile(abs, JSON.stringify(doc, null, 2), "utf8");
  return abs;
}

/** Convert a local path to a `file://` URI for SARIF's `uriBaseId`. */
function pathToFileUri(p: string): string {
  const abs = isAbsolute(p) ? p : join(process.cwd(), p);
  // On Windows, replace backslashes and add the drive-letter prefix.
  if (process.platform === "win32") {
    return "file:///" + abs.replace(/\\/g, "/").replace(/^\/+/, "");
  }
  return "file://" + abs;
}
