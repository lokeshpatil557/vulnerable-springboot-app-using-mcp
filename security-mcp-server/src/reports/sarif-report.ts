/** SARIF-shaped JSON report. Not full SARIF 2.1.0 — but close enough for most dashboards. */
import type { SecurityFinding } from "../core/finding.js";
import type { ReportMeta } from "./report-engine.js";
import { levelFromSarif } from "../core/severity.js";

export function renderSarifReport(findings: SecurityFinding[], meta: ReportMeta): string {
  const rules = new Map<string, { id: string; name: string; shortDescription: string }>();
  for (const f of findings) {
    if (!rules.has(f.ruleId)) {
      rules.set(f.ruleId, {
        id: f.ruleId,
        name: f.ruleId,
        shortDescription: { text: f.message.slice(0, 200) } as unknown as string,
      });
    }
  }
  const doc = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "security-mcp-server",
            version: "0.1.0",
            rules: [...rules.values()],
          },
        },
        invocations: [
          {
            executionSuccessful: true,
            startTimeUtc: meta.startedAt,
            endTimeUtc: meta.finishedAt,
          },
        ],
        results: findings.map((f) => ({
          ruleId: f.ruleId,
          ruleIndex: [...rules.keys()].indexOf(f.ruleId),
          level: levelFromSarif(f.severity),
          message: { text: f.message },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: f.path },
                region: {
                  startLine: f.location.startLine,
                  endLine: f.location.endLine ?? f.location.startLine,
                },
              },
            },
          ],
          partialFingerprints: { primary: f.fingerprint },
          properties: {
            severity: f.severity,
            confidence: f.confidence,
            category: f.category,
            cwe: f.cwe,
            cve: f.cve,
            owasp: f.owasp,
            fix: f.fix,
          },
        })),
      },
    ],
  };
  return JSON.stringify(doc, null, 2);
}
