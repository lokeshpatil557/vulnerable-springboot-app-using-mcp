/**
 * Zod input schemas for every MCP tool exposed by this server.
 * Schemas are exported individually so they can be reused in tests
 * and referenced by name from the tool registry.
 */
import { z } from "zod";

/** A repo-relative or absolute path the caller is targeting. */
export const RepoPath = z.string().min(1).describe("Path inside the repo root. May be a file or a directory.");

export const ScanDirectoryInput = z.object({
  path: RepoPath.optional().describe("Directory to scan. Defaults to repo root."),
  scanners: z
    .array(z.enum(["semgrep", "gitleaks", "trivy"]))
    .optional()
    .describe("Subset of scanners to run. Defaults to all available."),
  parallel: z.boolean().optional().default(true),
});

export const IdentifyCodebaseInput = z.object({
  path: RepoPath.optional().describe("Path to identify. Defaults to repo root."),
});

export const DetectVulnerabilitiesInput = z.object({
  path: RepoPath.optional(),
  includeRules: z.boolean().optional().default(true).describe("Include plugin-supplied extra rules."),
});

export const RunSastInput = z.object({
  path: RepoPath.optional(),
});

export const RunSecretScanInput = z.object({
  path: RepoPath.optional(),
});

export const ScanRepositoryInput = z.object({
  path: RepoPath.optional(),
  scanners: z.array(z.enum(["semgrep", "gitleaks", "trivy"])).optional(),
});

export const ScanFileInput = z.object({
  path: RepoPath.describe("File to scan (must be inside the repo)."),
  scanners: z.array(z.enum(["semgrep", "gitleaks", "trivy"])).optional(),
});

export const RunDependencyScanInput = z.object({
  path: RepoPath.optional(),
});

export const RunContainerScanInput = z.object({
  image: z.string().optional().describe("Image:tag to scan. If omitted, inferred from Dockerfile / compose."),
  path: RepoPath.optional(),
});

export const GenerateRemediationInput = z.object({
  findingId: z.string().describe("ID of a finding from the latest scan."),
});

export const ApplyRemediationInput = z.object({
  findingId: z.string().describe("ID of a finding from the latest scan."),
  acknowledged: z
    .boolean()
    .describe("Must be true. Required to confirm the caller wants the file modified."),
});

export const VerifyFixInput = z.object({
  findingIds: z.array(z.string()).min(1).describe("Finding IDs to verify."),
});

export const GenerateSecurityReportInput = z.object({
  format: z.enum(["json", "markdown", "sarif"]).optional().default("markdown"),
  scanId: z.string().optional().describe("Scan ID. Defaults to the most recent."),
});

export const ComplianceCheckInput = z.object({
  framework: z.enum(["owasp-top-10", "owasp-api-top-10", "cwe"]).optional().default("owasp-top-10"),
  scanId: z.string().optional(),
});

export const GenerateSbomInput = z.object({
  format: z.enum(["cyclonedx", "spdx"]).optional().default("cyclonedx"),
  path: RepoPath.optional(),
});

export const SupportedStacksInput = z.object({}).strict();

export const ListSecurityRulesInput = z.object({
  scanner: z.enum(["semgrep", "gitleaks", "trivy", "all"]).optional().default("all"),
});
