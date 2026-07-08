# Required scanners

The `security-mcp-server` is a **wrapper** around three external
scanner CLIs. The MCP server does not include them in the repository —
each developer and each CI runner must install them on the host.

This document lists the supported versions, the install matrix per
platform, and the rationale for not vendoring the binaries.

## Why we don't commit the scanners

Vendoring (i.e. committing the binaries) was considered and rejected:

- **Size.** `semgrep` is ~80 MB, `gitleaks` ~25 MB, `trivy` ~60 MB.
  Three releases per year × three scanners ≈ half a gigabyte of
  binary churn in `git log`.
- **License.** Each tool ships under its own license (Semgrep: LGPL-2.1,
  Gitleaks: MIT, Trivy: Apache-2.0). Vendoring obliges us to maintain
  third-party LICENSE files in-tree and re-verify them on every upgrade.
- **Cross-OS confusion.** A vendored Linux ELF binary on a Windows dev
  machine is useless. Per-platform vendor dirs multiply the size by 3
  and require us to build a custom matrix at every release.
- **CI drift.** A vendored binary pinned to a snapshot cannot be
  auto-updated. Every CVE in `semgrep`/`gitleaks`/`trivy` would require
  a code review and a commit before CI sees the fix.

## Supported versions

| Scanner   | Minimum tested | Recommended | Notes                                                |
|-----------|----------------|-------------|------------------------------------------------------|
| `semgrep` | 1.40.0         | 1.95.0+     | Older versions predate several OWASP rule packs.     |
| `gitleaks`| 8.18.0         | 8.18.4+     | `version` flag (vs. `--version`) was added in 8.18.  |
| `trivy`   | 0.50.0         | 0.50.1+     | CycloneDX SBOM schema changed in 0.50.               |

The `ToolManager` records the actual installed version in its
`ResolvedTool.version` field. We do **not** fail-fast on a below-minimum
version; we just surface the version in the per-tool `unavailable[]`
array so the operator can decide. Pin a stricter floor in CI by setting
`SCANNER_FAIL_FAST=1` and adding a wrapper check on `orchestrator.tools`.

## Install matrix

### Linux

| Scanner   | Debian/Ubuntu                                           | RHEL/Fedora                                       | Arch                                             |
|-----------|---------------------------------------------------------|---------------------------------------------------|--------------------------------------------------|
| `semgrep` | `pipx install semgrep` or `pip install --user semgrep`  | `pipx install semgrep` or `pip install --user`    | `yay -S semgrep` (AUR)                           |
| `gitleaks`| download GitHub release tarball (script handles this)   | `dnf install` from `gitleaks` repo                | `yay -S gitleaks` (AUR)                          |
| `trivy`   | add `aquasecurity/trivy-repo` apt repo, then `apt install trivy` | add `aquasecurity/trivy-repo` rpm repo, then `dnf install trivy` | `yay -S trivy` (AUR)                             |

### macOS

`brew install semgrep gitleaks trivy` covers all three.

### Windows

| Scanner   | `winget`                                | `scoop`              | `choco`              |
|-----------|-----------------------------------------|----------------------|----------------------|
| `semgrep` | `winget install --id Semgrep.Semgrep`   | `scoop install semgrep` | `choco install semgrep` |
| `gitleaks`| `winget install --id GitHub.gitleaks`   | `scoop install gitleaks` | `choco install gitleaks` |
| `trivy`   | `winget install --id AquaSecurity.Trivy`| `scoop install trivy` | `choco install trivy` |

`semgrep` is a Python package on every platform, so `pip install --user
semgrep` (or `pipx install semgrep`) is also a valid cross-platform
fallback.

## Per-developer workflow

1. Clone the repo.
2. `cd security-mcp-server`
3. `npm install`
4. `npm run setup:scanners` (POSIX) or
   `powershell -ExecutionPolicy Bypass -File scripts/setup-scanners.ps1`
   (Windows). Idempotent — re-runs are a no-op when already up to date.
5. `node dist/index.js --print-config` — verify the resolved config
   shows `status: "ok"` for every scanner in the boot log.
6. (Optional) `export SEMGREP_PATH=/custom/path` (or set the equivalent
   in your shell rc) to point at a non-standard install location.
7. Add the server to your MCP host (see the repo `README.md`).

## CI workflow

The reference workflow at
`.github/workflows/scanners-ci-example.yml` shows the recommended job
shape. The key step is:

```yaml
- name: Install scanners
  run: |
    cd security-mcp-server
    npm run setup:scanners
```

…followed by `SCANNER_FAIL_FAST=1 node dist/index.js …` when you want
the build to fail on a missing scanner.

## Where the binaries land after install

| Package manager | Install prefix           | PATH entry                |
|-----------------|--------------------------|---------------------------|
| Homebrew (mac)  | `/opt/homebrew/bin`      | already on PATH           |
| Homebrew (linux)| `/home/linuxbrew/.linuxbrew/bin` | add to rc if missing |
| `apt`           | `/usr/bin`               | already on PATH           |
| `pip install --user` | `~/.local/bin`       | add to PATH if missing    |
| `pipx`          | `~/.local/bin`           | add to PATH if missing    |
| `winget`        | `%LOCALAPPDATA%\Microsoft\WinGet\…` | already on PATH |
| `scoop`         | `%USERPROFILE%\scoop\shims` | already on PATH       |
| `choco`         | `%ProgramData%\chocolatey\bin` | already on PATH    |

The `ToolManager` walks `PATH` (`which` on POSIX, `where` on Windows),
so the developer's responsibility ends at "make sure the binary is on
PATH, or set the `*_PATH` env var".

## Re-pointing a scanner at a custom location

If you need to use a different binary — for example, a vendored release
you keep under `vendor/scanners/` for reproducibility — set the
override env var and the manager will pick it up on next boot:

```bash
export SEMGREP_PATH="$PWD/vendor/scanners/semgrep"
export GITLEAKS_PATH="$PWD/vendor/scanners/gitleaks"
export TRIVY_PATH="$PWD/vendor/scanners/trivy"
```

No code changes are required. The same mechanism is what CI uses to
pin to a specific release in a hardened pipeline.

## Verifying a healthy install

Run the version probes by hand to confirm the binaries are wired up:

```bash
semgrep --version     # ≥ 1.40.0
gitleaks version      # ≥ 8.18.0
trivy --version       # ≥ 0.50.0
```

Then start the server with `SCANNER_FAIL_FAST=1`:

```bash
SCANNER_FAIL_FAST=1 node dist/index.js --print-config
```

If everything is wired up correctly the server prints the resolved
config and exits with code 0. If any scanner is missing, the server
writes a `Required scanner(s) unavailable:` block to stderr listing
each missing tool with its install hint, and exits with code 1.
