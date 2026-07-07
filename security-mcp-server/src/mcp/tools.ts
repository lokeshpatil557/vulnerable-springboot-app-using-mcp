/**
 * MCP tool registration. Every public tool is registered exactly once.
 * To add a new tool: drop a file alongside this one that exports
 * `register(server, ctx): void`, then import + call it from `registerAllTools`.
 */
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { ScanContext } from "../core/scan-context.js";

import { registerScanDirectory } from "../tools/scan-directory.js";
import { registerIdentifyCodebase } from "../tools/identify-codebase.js";
import { registerDetectVulnerabilities } from "../tools/detect-vulnerabilities.js";
import { registerRunSast } from "../tools/run-sast.js";
import { registerRunSecretScan } from "../tools/run-secret-scan.js";
import { registerScanRepository } from "../tools/scan-repository.js";
import { registerScanFile } from "../tools/scan-file.js";
import { registerRunDependencyScan } from "../tools/run-dependency-scan.js";
import { registerRunContainerScan } from "../tools/run-container-scan.js";
import { registerGenerateRemediation } from "../tools/generate-remediation.js";
import { registerApplyRemediation } from "../tools/apply-remediation.js";
import { registerVerifyFix } from "../tools/verify-fix.js";
import { registerGenerateSecurityReport } from "../tools/generate-security-report.js";
import { registerComplianceCheck } from "../tools/compliance-check.js";
import { registerGenerateSbom } from "../tools/generate-sbom.js";
import { registerSupportedStacks } from "../tools/supported-stacks.js";
import { registerListSecurityRules } from "../tools/list-security-rules.js";

export function registerAllTools(server: McpServer, ctx: ScanContext): void {
  registerScanDirectory(server, ctx);
  registerIdentifyCodebase(server, ctx);
  registerDetectVulnerabilities(server, ctx);
  registerRunSast(server, ctx);
  registerRunSecretScan(server, ctx);
  registerScanRepository(server, ctx);
  registerScanFile(server, ctx);
  registerRunDependencyScan(server, ctx);
  registerRunContainerScan(server, ctx);
  registerGenerateRemediation(server, ctx);
  registerApplyRemediation(server, ctx);
  registerVerifyFix(server, ctx);
  registerGenerateSecurityReport(server, ctx);
  registerComplianceCheck(server, ctx);
  registerGenerateSbom(server, ctx);
  registerSupportedStacks(server, ctx);
  registerListSecurityRules(server, ctx);
}
