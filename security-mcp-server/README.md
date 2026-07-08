# security-mcp-server

A Model Context Protocol (MCP) server for security scanning, tech-stack detection, and verified remediation. Scans the **current Git repository** for SAST, secrets, dependency / container / IaC vulnerabilities, and provides an opt-in `apply_remediation` tool that creates a backup and rolls back on regression.

Designed to run as a Claude Code MCP server over **stdio**.

---

## Features

- **17 MCP tools** — `scan_directory`, `identify_codebase`, `detect_vulnerabilities`, `run_sast`, `run_secret_scan`, `scan_repository`, `scan_file`, `run_dependency_scan`, `run_container_scan`, `generate_remediation`, `apply_remediation`, `verify_fix`, `generate_security_report`, `compliance_check`, `generate_sbom`, `_supported_stacks`, `list_security_rules`.
- **Three scanner integrations** — `semgrep` (SAST), `gitleaks` (secrets), `trivy` (deps, container, IaC, SBOM).
- **Graceful degradation** — tools that need a missing scanner return a structured `tool_unavailable` error; the rest of the server still works.
- **External-tool discovery** — a `ToolManager` walks env → project-local → `PATH` (no hardcoded absolute paths) and records each scanner's resolved path, version, and install hint. Opt-in fail-fast via `SCANNER_FAIL_FAST=1`. See [`docs/REQUIRED_SCANNERS.md`](./docs/REQUIRED_SCANNERS.md) for the install matrix and CI guidance.
- **Stack detection** for 12 stacks (Java + Spring Boot, .NET / ASP.NET, Express.js, NestJS, Django, Flask, FastAPI, React, Angular, Vue.js, microservices, containerized, monolith fallback). Adding a stack = one file in `src/adapters/`.
- **Repo-root sandbox** — every path arg is asserted inside the resolved Git root before any FS read, write, or child-process invocation.
- **Read-only by default** — `apply_remediation` is the only mutating tool and requires `acknowledged: true`; it always backs up the file and rolls back on verification failure.
- **Audit log** — every tool call recorded as redacted JSONL at `<repo>/.security-mcp/audit.jsonl`.
- **Normalized findings** — `id`, `ruleId`, `level`, `severity`, `message`, `location{path,startLine,endLine}`, `cwe[]`, `cve?[]`, `owasp?[]`, `category`, `tool{name,version}`, `fix?{description,diff}`, `fingerprint`.
- **Reports** — JSON (SARIF-shaped), Markdown (severity-grouped, OWASP/CWE breakdown), PR description.

---

## Requirements

- **Node.js >= 20** (the `engines` field enforces this). If you don't have Node, install it first: <https://nodejs.org/> or `winget install OpenJS.NodeJS.LTS` on Windows.
- **Scanner CLIs (required, but not vendored)** — `semgrep`, `gitleaks`, `trivy`. The MCP server discovers them on `PATH` (or via `SEMGREP_PATH` / `GITLEAKS_PATH` / `TRIVY_PATH`); each developer and each CI runner installs them on the host. The repo deliberately does **not** commit the binaries. Run `npm run setup:scanners` after `npm install` to install everything on a single machine; see [`docs/REQUIRED_SCANNERS.md`](./docs/REQUIRED_SCANNERS.md) for the full per-OS install matrix and the rationale.
  - [`semgrep`](https://docs.semgrep.dev/) — `pip install semgrep` (or `pipx install semgrep` / `brew install semgrep` / `winget install Semgrep.Semgrep` / `scoop install semgrep` / `choco install semgrep`).
  - [`gitleaks`](https://github.com/gitleaks/gitleaks) — `brew install gitleaks` / `scoop install gitleaks` / `choco install gitleaks` / `winget install --id GitHub.gitleaks`.
  - [`trivy`](https://trivy.dev/) — `brew install trivy` / `scoop install trivy` / `choco install trivy` / `winget install --id AquaSecurity.Trivy` (Trivy downloads its vulnerability DB on first run; this can take 30–120 s).

---

## Install & build

The MCP server is registered with Claude Code through a **project-scoped
`.mcp.json` at the monorepo root** (one level up from this folder). It
references `dist/index.js` here using a `${CLAUDE_PROJECT_DIR:-.}`
variable, so every teammate gets the same registration without editing
a path.

```bash
# from the monorepo root
cd security-mcp-server
npm install
npm run typecheck   # tsc --noEmit
npm test            # vitest run
npm run build       # esbuild → dist/index.js
```

You can also run the source directly without a build step:

```bash
npm run dev   # tsx watch src/index.ts
```

> If you cloned the repo into a non-standard location and `dist/` is
> missing, the server will fail to spawn from `.mcp.json`. Run
> `npm run build` (above) — `dist/` is gitignored so each machine owns
> its own copy.

---

## Run as an MCP server

The server speaks the MCP protocol over **stdio**. The host (Claude Code) is responsible for spawning it and exchanging JSON-RPC frames on stdin/stdout. All server logging is written to **stderr** so the protocol stream on stdout stays clean.

### Add to Claude Code

**Recommended — project-scoped (no path editing required):** a
`.mcp.json` is committed at the monorepo root. Open Claude Code from
the repo root and the server is registered automatically for every
team member:

```bash
# from the monorepo root
claude
# then inside Claude Code, run: /mcp
# → "security-mcp-server" should show as connected
```

The path inside `.mcp.json` is
`${CLAUDE_PROJECT_DIR:-.}/security-mcp-server/dist/index.js`, which
Claude Code resolves to the absolute path of *your* checkout at spawn
time. No `claude mcp add` call, no per-machine edits.

**The same `.mcp.json` works for every app repo.** No `REPO_ROOT` is
pinned in the env block — the server auto-detects the Git repo to
scan by walking up from Claude Code's launch directory until it hits
a `.git` entry. So to switch apps, `cd` into the repo you want to
work on before launching Claude:

```bash
cd ~/work/billing-service
claude                       # scans billing-service
```

```bash
cd ~/work/checkout-app
claude                       # scans checkout-app
```

The registration is identical for every teammate and every app; only
the launch directory changes. To scan two repos in parallel, open a
second Claude Code session in the other repo.

**Escape hatch — per-user `claude mcp add`** (only if you cannot put
`.mcp.json` in the repo root). Adjust the path to match your checkout:

```bash
# POSIX (bash / zsh):
claude mcp add security-mcp-server -- node "$PWD/dist/index.js"

# Windows PowerShell:
claude mcp add security-mcp-server -- node "$PWD\dist\index.js"

# Override the default Git repo root (otherwise the server walks up to the
# nearest .git from the calling Claude Code session's CWD):
claude mcp add security-mcp-server \
  --env REPO_ROOT="/absolute/path/to/your/repo" \
  -- node "$PWD/dist/index.js"
```

See [`examples/claude_code_add.sh`](./examples/claude_code_add.sh) for a one-liner you can paste.

### Manual smoke test

```bash
# Run the server. It will block on stdin; send a JSON-RPC initialize frame to
# start, or just use a real MCP client.
#
# No --repo-root: the server walks up from cwd to the nearest .git.
node dist/index.js

# Equivalent — point at a specific repo explicitly:
node dist/index.js --repo-root "../sprint_boot_applications_demo_git"
```

A `--print-config` flag prints the resolved config and exits without binding stdio:

```bash
node dist/index.js --print-config
```

---

## Configuration

All configuration is via environment variables (and CLI flags where noted). Defaults shown.

| Env var | Default | Description |
|---|---|---|
| `REPO_ROOT` | `auto` | Absolute path to the Git repo to scan. `auto` walks up from CWD. Override with `--repo-root` on the CLI. |
| `LOG_LEVEL` | `info` | One of `trace`, `debug`, `info`, `warn`, `error`, `fatal`. |
| `AUDIT_LOG_PATH` | `.security-mcp/audit.jsonl` | Relative to `REPO_ROOT` (or absolute). |
| `SCAN_TIMEOUT_MS` | `300000` (5 min) | Per-scanner timeout. Set to `900000` for `trivy fs` on slow networks. |
| `MAX_CONCURRENT_SCANNERS` | `2` | `p-limit` cap on parallel scanner execution. |
| `SEMGREP_PATH` | `semgrep` | Absolute path to the `semgrep` binary (or name on PATH). |
| `GITLEAKS_PATH` | `gitleaks` | Same. |
| `TRIVY_PATH` | `trivy` | Same. |
| `INCLUDE_RULE_SETS` | _(unset)_ | Comma-separated Semgrep rule packs, e.g. `p/owasp-top-ten,p/secrets`. |
| `REDACT_IN_REPORTS` | `true` | Mask secret values in reports to last-4-only. |
| `SCANNER_FAIL_FAST` | `false` | When `1` / `true`, the server exits at boot if any of semgrep / gitleaks / trivy is missing. Default is "off" so the server still starts and reports missing tools via `unavailable[]`. Set this in CI and on first bootstrap of a new dev machine. |

### External-tool resolution

The server's `ToolManager` discovers each scanner in this order:

1. The matching `*_PATH` env var (if set and points at an executable).
2. `<projectRoot>/node_modules/.bin/<name>` and `<projectRoot>/bin/<name>` (project-local installs).
3. `PATH` — via `which` on POSIX, `where` on Windows.

No absolute paths are hardcoded; multiple developers on different machines (and CI runners) all work without any code changes. See [`docs/REQUIRED_SCANNERS.md`](./docs/REQUIRED_SCANNERS.md) for the full resolution rules, supported versions, and the per-OS install matrix.

### CLI flags

```
--repo-root <path>   Override REPO_ROOT for this invocation
--print-config       Print resolved config as JSON and exit
-v, --version        Print version
-h, --help           Help
```

---

## Tool reference

| Tool | Description |
|---|---|
| `scan_directory` | Run all available scanners against the repo. |
| `identify_codebase` | Detect tech stack(s) via the static adapter registry. |
| `detect_vulnerabilities` | Like `scan_directory` but lets the caller pick scanner IDs and rule packs; merges any stack-specific Semgrep rule fragments. |
| `run_sast` | Semgrep only. |
| `run_secret_scan` | Gitleaks only. |
| `scan_repository` | Alias of `scan_directory`. |
| `scan_file` | Single file. Dispatches by extension (config/secret-bearing files → gitleaks; lockfiles/manifests → trivy fs; source → semgrep). |
| `run_dependency_scan` | Trivy fs (CVE in OS packages & language dependencies). |
| `run_container_scan` | Resolves an image (from `image` arg → Dockerfile `FROM` → docker-compose `image:`) and runs Trivy image. |
| `generate_remediation` | Read-only. Returns a unified diff. Persists a record under `.security-mcp/remediations/<id>.json`. |
| `apply_remediation` | Requires `acknowledged: true`. Backs up, applies, re-scans, rolls back on regression. |
| `verify_fix` | Re-runs scanners and reports `fixed` / `still_present` / `not_found_in_storage` per finding ID. |
| `generate_security_report` | Writes JSON + Markdown for a prior scan. |
| `compliance_check` | Aggregates by severity, OWASP, CWE. |
| `generate_sbom` | Trivy CycloneDX SBOM under `.security-mcp/sbom/`. |
| `_supported_stacks` | Static list of registered stack adapters. |
| `list_security_rules` | Static rule-pack catalogue for each scanner. |

---

## Security model

1. **Repo-root sandbox.** `paths.resolveRepoRoot` walks up from CWD until it finds a `.git` entry (file or dir). Every path arg the server receives is normalized and asserted inside that root before any FS read, write, or child-process call. Tools throw `path_escape` if a caller tries to walk outside the boundary.
2. **No stdout writes in stdio mode.** All logging goes to stderr (or the audit file) so the MCP JSON-RPC stream on stdout is never corrupted.
3. **No auto-apply.** `apply_remediation` is the only mutating tool, requires `acknowledged: true`, always creates a backup under `.security-mcp/backups/<iso-timestamp>/<rel-path>`, and re-runs the producing scanner before declaring success. If the finding persists or new findings appear, the file is rolled back and the response includes `rolledBack: true`.
4. **No shell.** All child processes are spawned via `execa` with array args (`shell: false`). User-supplied path args are passed after a `--` sentinel where the scanner supports it (e.g. `trivy fs -- <path>`).
5. **Timeouts.** Every scanner call is wrapped in `withTimeout`; on Windows timeouts cascade to `taskkill /pid <pid> /T /F` to kill grandchildren.
6. **Secret redaction.** The audit logger redacts `args.password`, `args.token`, `args.secret`, `args.apiKey`, `args.authorization`, `args.headers.Authorization`, `args.cookie`. Gitleaks findings mask the raw secret value to last-4-only before being returned to the model.
7. **Input validation.** Every tool's input is a `zod` schema passed to `McpServer.registerTool`; failed validation produces `InvalidParams` automatically.
8. **Atomic file writes.** `writeTextFileAtomic` writes to a temp sibling, then `rename`s into place. NTFS and POSIX both guarantee this is atomic within a directory.

---

## Local smoke test (no scanners installed)

This machine does not have `semgrep`, `gitleaks`, or `trivy` on `PATH`. The server still works for everything that does not require an external binary:

```bash
node dist/index.js --repo-root "../sprint_boot_applications_demo_git"
```

In a Claude Code session pointed at the Spring Boot lab repo, expect:

- `identify_codebase` → `{ matches: [ { adapterId: "java-spring-boot", confidence: >=0.9, … }, { adapterId: "monolith", confidence: 0.2, … } ] }`.
- `scan_directory` → `{ findings: [], unavailable: [ { tool: "semgrep" }, { tool: "gitleaks" }, { tool: "trivy" } ] }` and an `unavailable` event in the audit log.
- `list_security_rules` → returns the static catalogue.
- `_supported_stacks` → returns the 12-adapter list.
- `run_container_scan` (without an `image` arg) → throws `no_image_found` (the lab has no Dockerfile).

---

## Directory layout (created at runtime)

```
<repo-root>/
└── .security-mcp/
    ├── audit.jsonl                    # append-only JSONL audit log
    ├── scans/
    │   └── scan-<timestamp>.json      # one file per scan_directory call
    ├── reports/
    │   ├── <scanId>.json              # generated by generate_security_report
    │   └── <scanId>.md                # ditto
    ├── sbom/
    │   └── trivy.cdx.json             # generated by generate_sbom
    ├── backups/
    │   └── <iso-timestamp>/           # one dir per apply_remediation
    └── remediations/
        └── <findingId>.json           # persisted proposal for apply_remediation
```

---

## Adding a new stack adapter

1. Open `src/adapters/detect.ts` and add a new `StackAdapter` (use one of the existing adapters as a template).
2. Add it to the `ADAPTERS` array in `src/adapters/registry.ts`.
3. Add a test in `tests/adapters-registry.test.ts` (just add the `id` to the expected set).
4. (Optional) Add language-specific Semgrep rules via `extraRules()`.

There is **no dynamic import or filesystem glob** — the registry is static, so the build step (or `tsx` dev mode) will catch a missing import at startup.

## CI / multi-developer setup

- **Per developer**: run `npm run setup:scanners` (POSIX) or `powershell -ExecutionPolicy Bypass -File scripts/setup-scanners.ps1` (Windows) once after cloning. Re-runs are idempotent.
- **CI**: see [`.github/workflows/scanners-ci-example.yml`](./.github/workflows/scanners-ci-example.yml) for a complete reference workflow covering `ubuntu-latest`, `macos-latest`, and `windows-latest`. The only step that varies per host is the scanner-installer invocation; everything else is the same.
- **Custom scanner locations**: set `SEMGREP_PATH` / `GITLEAKS_PATH` / `TRIVY_PATH` to the absolute path of the binary. The `ToolManager` honours the override without code changes.

---

## License

MIT — see [`LICENSE`](./LICENSE).
