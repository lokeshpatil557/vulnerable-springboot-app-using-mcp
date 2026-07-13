import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type { ToolContext, AnyMcpServer } from "../src/tools/_shared.js";
import { register as registerScanRepository } from "../src/tools/scan-repository.js";
import { register as registerGenerateSecurityReport } from "../src/tools/generate-security-report.js";
import { Config } from "../src/config.js";

describe("scan_repository persistence", () => {
  let tmpDir: string;
  let ctx: Partial<ToolContext>;
  let tools: Map<string, unknown>;

  beforeEach(async () => {
    tmpDir = await mkdtemp(join(tmpdir(), "scan-repo-test-"));
    tools = new Map();
    ctx = {
      repoRoot: tmpDir,
      logger: {
        info: () => {},
        warn: () => {},
        error: () => {},
        debug: () => {},
        trace: () => {},
        fatal: () => {},
        child: () => ctx.logger as any,
        level: "info",
      } as any,
      config: {
        repoRoot: tmpDir,
        logLevel: "info" as const,
        auditLogPath: join(tmpDir, ".security-mcp", "audit.jsonl"),
        scanTimeoutMs: 5000,
        maxConcurrentScanners: 1,
        perScannerBinaries: {},
        includeRuleSets: [],
        redactInReports: true,
        scannerFailFast: false,
        pathSafety: {
          allowedRoot: tmpDir,
          maxFileBytes: 26214400,
          maxRepoBytes: 1073741824,
          maxDiffBytes: 1048576,
          followSymlinks: false,
          allowApplyRemediation: false,
          blockedFiles: [],
          forbiddenAncestors: [],
        },
      } as Config,
      scanners: {} as any,
    };
  });

  afterEach(async () => {
    if (tmpDir) {
      try {
        await rm(tmpDir, { recursive: true, force: true });
      } catch {
        // ignore cleanup errors
      }
    }
  });

  it("scan_repository persists results to .security-mcp/scans/", async () => {
    const server = {
      tool: (name: string, desc: string, schema: any, handler: any) => {
        tools.set(name, { desc, schema, handler });
      },
    } as any;

    registerScanRepository(server, ctx as any);

    const scanRepoTool = tools.get("scan_repository") as any;
    expect(scanRepoTool).toBeDefined();

    // Call the tool handler
    const result = await scanRepoTool.handler({});

    // Check that a scanId was returned
    expect(result.ok).toBe(true);
    expect(result.data.scanId).toBeDefined();
    expect(result.data.scanId).toMatch(/^scan-\d+$/);

    // Check that the scan was persisted to disk
    const scanPath = join(tmpDir, ".security-mcp", "scans", `${result.data.scanId}.json`);
    const scanFile = await readFile(scanPath, "utf8");
    const scanData = JSON.parse(scanFile);

    expect(scanData.meta.scanId).toBe(result.data.scanId);
    expect(scanData.findings).toBeDefined();
    expect(Array.isArray(scanData.findings)).toBe(true);
  });

  it("scan_repository returns scanId in response", async () => {
    const server = {
      tool: (name: string, desc: string, schema: any, handler: any) => {
        tools.set(name, { desc, schema, handler });
      },
    } as any;

    registerScanRepository(server, ctx as any);

    const scanRepoTool = tools.get("scan_repository") as any;
    const result = await scanRepoTool.handler({});

    expect(result.ok).toBe(true);
    expect(result.data).toHaveProperty("scanId");
    expect(result.data).toHaveProperty("scanPath");
    expect(result.data.scanPath).toContain(".security-mcp/scans/");
  });
});
