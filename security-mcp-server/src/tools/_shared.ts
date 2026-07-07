import { z } from "zod";
export { z };
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { Logger } from "pino";
import type { Config } from "../config.js";
import type { AuditLogger } from "../audit.js";
import type { ScannerRegistry } from "../scanners/registry.js";
import type { SecurityOrchestrator } from "../orchestrator.js";
import { relativeToRepo } from "../paths.js";
import { monotonicMs } from "../util/time.js";
import { toMcpErrorBody } from "../errors.js";

/** Per-tool context injected at registration time. */
export interface ToolContext {
  repoRoot: string;
  config: Config;
  logger: Logger;
  audit: AuditLogger;
  scanners: ScannerRegistry;
  /** Composition root. Tools that need plugins / remediation should read from here. */
  orchestrator: SecurityOrchestrator;
  startedAt: number;
}

/** Common zod input schemas reused across tools. */
export const ScannerIds = z.enum(["semgrep", "gitleaks", "trivy"]);
export const ScanTarget = z.string().min(1).max(4096).optional();

export const RunScannersInput = z.object({
  includeRuleSets: z.array(z.string()).optional(),
  target: ScanTarget,
  ids: z.array(ScannerIds).optional(),
});

export const ScanFileInput = z.object({
  file: z.string().min(1).max(4096),
  scanners: z.array(ScannerIds).optional(),
});

export const GenerateRemediationInput = z.object({
  findingId: z.string().min(1).max(256),
  diff: z.string().optional(),
  description: z.string().optional(),
});

export const ApplyRemediationInput = z.object({
  findingId: z.string().min(1).max(256),
  diff: z.string().min(1),
  acknowledged: z.literal(true),
  description: z.string().optional(),
});

export const VerifyFixInput = z.object({
  findingIds: z.array(z.string().min(1).max(256)).min(1).max(100),
});

export const GenerateReportInput = z.object({
  scanId: z.string().min(1).max(256),
  destDir: z.string().optional(),
});

export const ComplianceCheckInput = z.object({
  scanId: z.string().optional(),
});

export const GenerateSbomInput = z.object({
  destPath: z.string().optional(),
});

export const ContainerScanInput = z.object({
  image: z.string().optional(),
});

export type McpResponseBody =
  | { ok: true; [k: string]: unknown }
  | { ok: false; code: string; message: string };

/**
 * Tool-call result envelope returned by every MCP tool. Matches the SDK's
 * `CallToolResult` shape: a `content` array of text blocks, plus an
 * optional `isError` flag for failures.
 */
export type ToolCallResult = {
  content: { type: "text"; text: string }[];
  isError?: boolean;
};

/** Wrap a tool handler with audit logging and uniform error handling. */
export function auditWrap(
  ctx: ToolContext,
  tool: string,
  args: unknown,
  fn: () => Promise<{ result: Record<string, unknown> }>,
): Promise<ToolCallResult> {
  const start = monotonicMs();
  return fn()
    .then(({ result }): ToolCallResult => {
      const findingCount =
        typeof (result as { findings?: unknown[] }).findings?.length === "number"
          ? ((result as { findings: unknown[] }).findings.length)
          : 0;
      ctx.audit.record({
        ts: new Date().toISOString(),
        tool,
        args,
        findingCount,
        durationMs: monotonicMs() - start,
        outcome: "ok",
        errorCode: null,
      });
      return { content: [{ type: "text", text: JSON.stringify({ ok: true, ...result }) }] };
    })
    .catch((err: unknown): ToolCallResult => {
      const outcome = /tool_unavailable|scanner.*not.*found/.test(String((err as { code?: string }).code ?? err))
        ? "unavailable"
        : "error";
      ctx.audit.record({
        ts: new Date().toISOString(),
        tool,
        args,
        findingCount: 0,
        durationMs: monotonicMs() - start,
        outcome,
        errorCode: (err as { code?: string }).code ?? "error",
      });
      return toMcpErrorBody(err);
    });
}

/** MCP-shaped success response. */
export function ok(result: Record<string, unknown>) {
  return Promise.resolve({ result });
}

/** Convert an absolute path to repo-relative for inclusion in responses. */
export function rel(repoRoot: string, abs: string): string {
  return relativeToRepo(repoRoot, abs);
}

/** Get the type-only server reference for handler registration. */
export type AnyMcpServer = McpServer;
