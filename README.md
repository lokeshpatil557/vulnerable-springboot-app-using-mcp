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

## One-time setup for the team

The MCP server is registered via a project-scoped `.mcp.json` at the
repo root, so **no one has to edit an absolute path or run
`claude mcp add`** — Claude Code picks it up automatically using
`${CLAUDE_PROJECT_DIR:-.}`, which it resolves to *your* checkout path
at spawn time. Every teammate gets an identical registration.

> The `:-.` part is a default fallback: Claude Code sets
> `CLAUDE_PROJECT_DIR` in the spawned server's environment, so the
> `${CLAUDE_PROJECT_DIR:-.}` expansion resolves to the absolute path
> of the project root (the directory containing `.mcp.json`). The
> default `.` is only used if the variable is somehow unset.

```bash
# 1. Clone the repo (any directory, any OS).
git clone <this-repo-url> vulnerable-springboot-app-using-mcp
cd vulnerable-springboot-app-using-mcp

# 2. Build the MCP server once on your machine.
#    (The dist/ artifact is gitignored — every machine builds its own copy.)
cd security-mcp-server
npm install
npm run build           # produces dist/index.js, which .mcp.json references
cd ..

# 3. Open Claude Code in the repo root.
claude
```

Inside Claude Code, run `/mcp` — `security-mcp-server` should appear
with status **connected**. If the build step is missing, `.mcp.json`
will still register the server but it will fail to spawn; rerun
`npm run build` inside `security-mcp-server/`.

### Scanning multiple application repositories

The same `.mcp.json` works for every app repo in the workspace —
there is no `REPO_ROOT` pinned. The server auto-detects the Git repo
to scan by walking up from Claude Code's launch directory until it
finds a `.git` entry. So to switch which app you're scanning:

```bash
cd ~/work/billing-service    # or any app repo
claude                        # launches with that app as the scan target
```

`security-mcp-server` is registered the same way in every repo; only
the launch directory changes. To compare two apps in parallel, open
a second Claude Code session in the other repo.

> Prefer this flow over `claude mcp add …`. The project-scoped
> `.mcp.json` lives in version control, so it stays in sync with the
> server source and a fresh `git pull` is all that's needed when the
> registration changes. See
> [`security-mcp-server/README.md`](./security-mcp-server/README.md)
> for an escape-hatch `claude mcp add` form if you can't put
> `.mcp.json` in your repo root.

---

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
