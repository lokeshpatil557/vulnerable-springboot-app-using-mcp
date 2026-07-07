import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { ToolContext } from "./_shared.js";
import * as scanDirectory from "./scan-directory.js";
import * as identifyCodebase from "./identify-codebase.js";
import * as detectVulnerabilities from "./detect-vulnerabilities.js";
import * as runSast from "./run-sast.js";
import * as runSecretScan from "./run-secret-scan.js";
import * as scanRepository from "./scan-repository.js";
import * as scanFile from "./scan-file.js";
import * as runDependencyScan from "./run-dependency-scan.js";
import * as runContainerScan from "./run-container-scan.js";
import * as generateRemediation from "./generate-remediation.js";
import * as applyRemediation from "./apply-remediation.js";
import * as verifyFix from "./verify-fix.js";
import * as generateSecurityReport from "./generate-security-report.js";
import * as complianceCheck from "./compliance-check.js";
import * as generateSbom from "./generate-sbom.js";
import * as supportedStacks from "./supported-stacks.js";
import * as listSecurityRules from "./list-security-rules.js";

/** Register every MCP tool on the given server instance. */
export function registerAllTools(server: McpServer, ctx: ToolContext): void {
  scanDirectory.register(server, ctx);
  identifyCodebase.register(server, ctx);
  detectVulnerabilities.register(server, ctx);
  runSast.register(server, ctx);
  runSecretScan.register(server, ctx);
  scanRepository.register(server, ctx);
  scanFile.register(server, ctx);
  runDependencyScan.register(server, ctx);
  runContainerScan.register(server, ctx);
  generateRemediation.register(server, ctx);
  applyRemediation.register(server, ctx);
  verifyFix.register(server, ctx);
  generateSecurityReport.register(server, ctx);
  complianceCheck.register(server, ctx);
  generateSbom.register(server, ctx);
  supportedStacks.register(server, ctx);
  listSecurityRules.register(server, ctx);
}
