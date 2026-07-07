/**
 * Typed error shapes used across the MCP server. Each carries a stable
 * `code` that downstream tooling (audit log, MCP response) can switch on.
 */

export class RepoRootNotFoundError extends Error {
  readonly code = "repo_root_not_found";
  constructor(public readonly startDir: string) {
    super(`No .git directory found above ${startDir}`);
    this.name = "RepoRootNotFoundError";
  }
}

export class PathEscapeError extends Error {
  readonly code = "path_escape";
  constructor(public readonly candidate: string, public readonly repoRoot: string) {
    super(`Path '${candidate}' resolves outside repo root '${repoRoot}'`);
    this.name = "PathEscapeError";
  }
}

export class ToolUnavailableError extends Error {
  readonly code = "tool_unavailable";
  constructor(public readonly tool: string, public readonly reason: string) {
    super(`Scanner '${tool}' unavailable: ${reason}`);
    this.name = "ToolUnavailableError";
  }
}

export class ScannerTimeoutError extends Error {
  readonly code = "scanner_timeout";
  constructor(public readonly scanner: string, public readonly timeoutMs: number) {
    super(`Scanner '${scanner}' timed out after ${timeoutMs}ms`);
    this.name = "ScannerTimeoutError";
  }
}

export class InvalidInputError extends Error {
  readonly code = "invalid_input";
  constructor(message: string) {
    super(message);
    this.name = "InvalidInputError";
  }
}

export class NoImageFoundError extends Error {
  readonly code = "no_image_found";
  constructor(public readonly repoRoot: string) {
    super(
      `No container image could be resolved for ${repoRoot}. ` +
        `Provide an 'image' argument, a FROM line in a Dockerfile, or an 'image:' entry in docker-compose*.yml.`,
    );
    this.name = "NoImageFoundError";
  }
}

export class RemediationNotFoundError extends Error {
  readonly code = "remediation_not_found";
  constructor(public readonly findingId: string) {
    super(`No prior remediation found for finding '${findingId}'`);
    this.name = "RemediationNotFoundError";
  }
}

export type McpErrorBody = {
  isError: true;
  content: { type: "text"; text: string }[];
};

export function toMcpErrorBody(err: unknown): McpErrorBody {
  let code = "internal_error";
  let message = "An unexpected error occurred";
  if (err && typeof err === "object" && "code" in err && typeof (err as { code: unknown }).code === "string") {
    code = (err as { code: string }).code;
  }
  if (err instanceof Error) {
    message = err.message;
  } else if (typeof err === "string") {
    message = err;
  }
  return {
    isError: true,
    content: [
      { type: "text", text: JSON.stringify({ ok: false, code, message }) },
    ],
  };
}
