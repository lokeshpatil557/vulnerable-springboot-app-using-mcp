import { describe, it, expect } from "vitest";
import { toMcpErrorBody, InvalidInputError, PathEscapeError, ToolUnavailableError, ScannerTimeoutError, NoImageFoundError, RemediationNotFoundError } from "../src/errors.js";

describe("errors", () => {
  it("toMcpErrorBody returns a structured MCP error body", () => {
    const body = toMcpErrorBody(new PathEscapeError("../etc", "/repo"));
    expect(body.isError).toBe(true);
    const parsed = JSON.parse(body.content[0]!.text);
    expect(parsed.code).toBe("path_escape");
    expect(parsed.message).toMatch(/resolves outside/);
  });

  it("typed errors carry the right code", () => {
    expect(new InvalidInputError("bad").code).toBe("invalid_input");
    expect(new ToolUnavailableError("semgrep", "missing").code).toBe("tool_unavailable");
    expect(new ScannerTimeoutError("trivy", 1000).code).toBe("scanner_timeout");
    expect(new NoImageFoundError("/r").code).toBe("no_image_found");
    expect(new RemediationNotFoundError("x").code).toBe("remediation_not_found");
  });

  it("handles non-Error throws", () => {
    const body = toMcpErrorBody("boom");
    const parsed = JSON.parse(body.content[0]!.text);
    expect(parsed.message).toBe("boom");
  });
});
