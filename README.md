# vulnerable-springboot-app-using-mcp

Finding vulnerabilities from the repo using the MCP server.

## Repository layout

- `security-mcp-server/` — the MCP server source. See
  [`security-mcp-server/README.md`](./security-mcp-server/README.md) for
  how to build, run, and integrate with Claude Code.
- `sprint_boot_applications_demo_git/` — the intentionally vulnerable
  Spring Boot lab the MCP server scans.
- `sprint_boot_applications_demo_git/.claude/` — the Claude Code
  agents, commands, and reports that drive the scan / remediate loop.

## External scanners

The MCP server wraps three external CLIs (`semgrep`, `gitleaks`,
`trivy`). They are **not** committed to the repo — each developer and
each CI runner installs them on the host. Resolution walks env vars
(`SEMGREP_PATH` / `GITLEAKS_PATH` / `TRIVY_PATH`) → project-local
`node_modules/.bin` → `PATH`. No hardcoded absolute paths.

- Install matrix and rationale:
  [`security-mcp-server/docs/REQUIRED_SCANNERS.md`](./security-mcp-server/docs/REQUIRED_SCANNERS.md)
- Setup scripts:
  [`security-mcp-server/scripts/setup-scanners.sh`](./security-mcp-server/scripts/setup-scanners.sh)
  (POSIX) and
  [`security-mcp-server/scripts/setup-scanners.ps1`](./security-mcp-server/scripts/setup-scanners.ps1)
  (Windows). Both are idempotent.
- Reference CI workflow:
  [`security-mcp-server/.github/workflows/scanners-ci-example.yml`](./security-mcp-server/.github/workflows/scanners-ci-example.yml)
  — copy this into your pipeline or adapt the per-host install step.

To set everything up on a fresh machine:

```bash
cd security-mcp-server
npm install
npm run setup:scanners    # POSIX; Windows: see scripts/setup-scanners.ps1
```

The `ToolManager` inside the server will detect the binaries on the
next boot. To make the server exit at boot if any scanner is missing,
set `SCANNER_FAIL_FAST=1` (recommended for CI).
