# security-mcp-server

A Model Context Protocol (MCP) server for security scanning, tech-stack detection, and verified remediation. Scans the **current Git repository** for SAST, secrets, dependency / container / IaC vulnerabilities, and provides an opt-in `apply_remediation` tool that creates a backup and rolls back on regression.

Designed to run as a Claude Code MCP server over **stdio**.

---

## Features

- **17 MCP tools** — `scan_directory`, `identify_codebase`, `detect_vulnerabilities`, `run_sast`, `run_secret_scan`, `scan_repository`, `scan_file`, `run_dependency_scan`, `run_container_scan`, `generate_remediation`, `apply_remediation`, `verify_fix`, `generate_security_report`, `compliance_check`, `generate_sbom`, `_supported_stacks`, `list_security_rules`.
- **Three scanner integrations** — `semgrep` (SAST), `gitleaks` (secrets), `trivy` (deps, container, IaC, SBOM).
- **Graceful degradation** — tools that need a missing scanner return a structured `tool_unavailable` error; the rest of the server still works.
- **Stack detection** for 12 stacks (Java + Spring Boot, .NET / ASP.NET, Express.js, NestJS, Django, Flask, FastAPI, React, Angular, Vue.js, microservices, containerized, monolith fallback). Adding a stack = one file in `src/adapters/`.
- **Repo-root sandbox** — every path arg is asserted inside the resolved Git root before any FS read, write, or child-process invocation.
- **Read-only by default** — `apply_remediation` is the only mutating tool and requires `acknowledged: true`; it always backs up the file and rolls back on verification failure.
- **Audit log** — every tool call recorded as redacted JSONL at `<repo>/.security-mcp/audit.jsonl`.
- **Normalized findings** — `id`, `ruleId`, `level`, `severity`, `message`, `location{path,startLine,endLine}`, `cwe[]`, `cve?[]`, `owasp?[]`, `category`, `tool{name,version}`, `fix?{description,diff}`, `fingerprint`.
- **Reports** — JSON (SARIF-shaped), Markdown (severity-grouped, OWASP/CWE breakdown), PR description.

---

## Requirements

- **Node.js >= 20** (the `engines` field enforces this). If you don't have Node, install it first: <https://nodejs.org/> or `winget install OpenJS.NodeJS.LTS` on Windows.
- Optional scanner CLIs (each is **independently optional**):
  - [`semgrep`](https://docs.semgrep.dev/) — `pip install semgrep` or download from <https://semgrep.dev/docs/getting-started>.
  - [`gitleaks`](https://github.com/gitleaks/gitleaks) — `brew install gitleaks` / `scoop install gitleaks` / `choco install gitleaks`.
  - [`trivy`](https://trivy.dev/) — `brew install trivy` / `scoop install trivy` / `choco install trivy` (Trivy downloads its vulnerability DB on first run; this can take 30–120 s).

---

## Install & build

```bash
cd C:/Users/Lenovo/Downloads/security-mcp-server
npm install
npm run typecheck   # tsc --noEmit
npm test            # vitest run
npm run build       # esbuild → dist/index.js
```

You can also run the source directly without a build step:

```bash
npm run dev   # tsx watch src/index.ts
```

---

## Run as an MCP server

The server speaks the MCP protocol over **stdio**. The host (Claude Code) is responsible for spawning it and exchanging JSON-RPC frames on stdin/stdout. All server logging is written to **stderr** so the protocol stream on stdout stays clean.

### Add to Claude Code

```bash
# Local install (recommended for development):
claude mcp add security-mcp-server -- node "C:/Users/Lenovo/Downloads/security-mcp-server/dist/index.js"

# OR via npm script (after npm link):
claude mcp add security-mcp-server -- security-mcp-server

# Override the default Git repo root (otherwise the server walks up to the
# nearest .git from the calling Claude Code session's CWD):
claude mcp add security-mcp-server \
  --env REPO_ROOT="C:/Users/Lenovo/path/to/your/repo" \
  -- node "C:/Users/Lenovo/Downloads/security-mcp-server/dist/index.js"
```

See [`examples/claude_code_add.sh`](./examples/claude_code_add.sh) for a one-liner you can paste.

### Manual smoke test

```bash
# Run the server. It will block on stdin; send a JSON-RPC initialize frame to
# start, or just use a real MCP client.
node dist/index.js --repo-root "C:/Users/Lenovo/Downloads/sprint_boot_applications_demo_git"
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
node dist/index.js --repo-root "C:/Users/Lenovo/Downloads/sprint_boot_applications_demo_git"
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

---

## License

MIT — see [`LICENSE`](./LICENSE).
