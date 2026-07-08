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

export class TraversalError extends Error {
  readonly code = "path_traversal";
  constructor(public readonly candidate: string) {
    super(`Path '${candidate}' contains traversal segments (.., encoded, or NUL bytes)`);
    this.name = "TraversalError";
  }
}

export class ForbiddenAncestorError extends Error {
  readonly code = "forbidden_ancestor";
  constructor(public readonly candidate: string, public readonly ancestor: string) {
    super(
      `Path '${candidate}' is under forbidden ancestor '${ancestor}' ` +
        `(home, parent of home, or filesystem root are not allowed)`,
    );
    this.name = "ForbiddenAncestorError";
  }
}

export class BlockedFileError extends Error {
  readonly code = "blocked_file";
  constructor(public readonly candidate: string, public readonly pattern: string) {
    super(`Path '${candidate}' matches blocked pattern '${pattern}'`);
    this.name = "BlockedFileError";
  }
}

export class SymlinkEscapeError extends Error {
  readonly code = "symlink_escape";
  constructor(public readonly candidate: string, public readonly target: string) {
    super(
      `Symlink '${candidate}' resolves to '${target}' which is outside the allowed root`,
    );
    this.name = "SymlinkEscapeError";
  }
}

export class PayloadTooLargeError extends Error {
  readonly code = "payload_too_large";
  constructor(
    public readonly what: "file" | "diff" | "repo",
    public readonly actualBytes: number,
    public readonly maxBytes: number,
  ) {
    super(
      `${what} payload of ${actualBytes} bytes exceeds limit of ${maxBytes} bytes`,
    );
    this.name = "PayloadTooLargeError";
  }
}

export class BinaryFileError extends Error {
  readonly code = "binary_file";
  constructor(public readonly candidate: string) {
    super(
      `File '${candidate}' appears to be binary; remediation is only allowed for text files`,
    );
    this.name = "BinaryFileError";
  }
}

export class ApplyPolicyDeniedError extends Error {
  readonly code = "apply_policy_denied";
  constructor(public readonly repoRoot: string) {
    super(
      `apply_remediation is disabled by policy (ALLOW_APPLY_REMEDIATION=1 required) for repo '${repoRoot}'`,
    );
    this.name = "ApplyPolicyDeniedError";
  }
}

export class ToolUnavailableError extends Error {
  readonly code = "tool_unavailable";
  constructor(public readonly tool: string, public readonly reason: string) {
    super(`Scanner '${tool}' unavailable: ${reason}`);
    this.name = "ToolUnavailableError";
  }
}

/**
 * Thrown by the `ToolManager` (and surfaced by the orchestrator) when
 * one or more scanners are unavailable AND the manager is in `failFast`
 * mode (opt-in via `SCANNER_FAIL_FAST=1`). Carries the full list of
 * missing tools and the per-tool install hints so the operator gets a
 * single, actionable error message instead of one-at-a-time.
 *
 * Does **not** extend `ToolUnavailableError` because the parent's
 * `readonly code: "tool_unavailable"` is a literal type — narrowing it
 * in a child is not assignable. We keep the `code`-string-based
 * matching contract: callers that previously did
 * `if (err.code === "tool_unavailable")` will not match this class,
 * and that is the intended behaviour (a missing dependency is a
 * different class of failure).
 */
export interface ScannerDependencyDetail {
  readonly key: string;
  readonly reason: string;
  readonly binaryPath: string | null;
  readonly status: string;
}

export class ScannerDependencyMissingError extends Error {
  readonly code = "scanner_dependency_missing";
  readonly missing: string[];
  readonly details: ReadonlyArray<ScannerDependencyDetail>;

  constructor(details: ReadonlyArray<ScannerDependencyDetail>) {
    const lines = details.map(
      (d) => `  - ${d.key}: ${d.reason}${d.binaryPath ? ` (last attempt: ${d.binaryPath})` : ""}`,
    );
    const summary = `Required scanner(s) unavailable:\n${lines.join("\n")}`;
    super(summary);
    this.name = "ScannerDependencyMissingError";
    this.missing = details.map((d) => d.key);
    this.details = details;
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
