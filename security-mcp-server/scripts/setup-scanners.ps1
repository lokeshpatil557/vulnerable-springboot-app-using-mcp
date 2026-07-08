# setup-scanners.ps1
# Installs the three external scanner CLIs that the security-mcp-server
# depends on (semgrep, gitleaks, trivy) on Windows.
#
# Designed to be idempotent: re-running is a no-op when already at the
# documented minimum versions. Always exits non-zero on any failure with
# a clear remediation hint written to stderr.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File scripts/setup-scanners.ps1
#
# Environment overrides:
#   PREFERRED_PKG_MANAGER = "winget" | "scoop" | "choco"   (default: auto)
#   SEMGREP_VERSION        (default: 1.95.0 - install pinned to this if set)
#   GITLEAKS_VERSION       (default: 8.18.4)
#   TRIVY_VERSION          (default: 0.50.1)
#
# Exit codes:
#   0  All three scanners installed and on PATH.
#   1  At least one scanner could not be installed.
#   2  Required prerequisite missing (e.g. no supported package manager).


[CmdletBinding()]
param(
  [string]$PreferredPkgManager = $env:PREFERRED_PKG_MANAGER,
  [string]$SemgrepVersion = $env:SEMGREP_VERSION,
  [string]$GitleaksVersion = $env:GITLEAKS_VERSION,
  [string]$TrivyVersion = $env:TRIVY_VERSION
)

if ([string]::IsNullOrWhiteSpace($SemgrepVersion)) {
    $SemgrepVersion = "1.95.0"
}

if ([string]::IsNullOrWhiteSpace($GitleaksVersion)) {
    $GitleaksVersion = "8.18.4"
}

if ([string]::IsNullOrWhiteSpace($TrivyVersion)) {
    $TrivyVersion = "0.50.1"
}


$ErrorActionPreference = "Stop"

function Write-Section {
  param([string]$Title)
  Write-Host ""
  Write-Host "==> $Title" -ForegroundColor Cyan
}

function Test-Binary {
  # Returns the resolved path on success, $null on failure.
  param([string]$Name)
  $cmd = Get-Command $Name -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }
  return $null
}

function Install-Semgrep {
  Write-Section "semgrep (target >= 1.40.0)"
  $existing = Test-Binary "semgrep"
  if ($existing) {
    $ver = (& semgrep --version 2>$null | Select-Object -First 1) -replace "^semgrep\s*", ""
    Write-Host "  already installed: $existing ($ver)" -ForegroundColor Green
    return $existing
  }
  if (Get-Command py -ErrorAction SilentlyContinue) {
    Write-Host "  installing via 'py -m pip install --user semgrep'..."
    & py -m pip install --user "semgrep>=$SemgrepVersion"
  } elseif (Get-Command python -ErrorAction SilentlyContinue) {
    Write-Host "  installing via 'python -m pip install --user semgrep'..."
    & python -m pip install --user "semgrep>=$SemgrepVersion"
  } elseif (Get-Command pip -ErrorAction SilentlyContinue) {
    Write-Host "  installing via 'pip install --user semgrep'..."
    & pip install --user "semgrep>=$SemgrepVersion"
  } else {
    Write-Error "  no Python interpreter found on PATH. Install Python 3.10+ from https://python.org and re-run, or use 'winget install Semgrep.Semgrep'."
    return $null
  }
  return (Test-Binary "semgrep")
}

function Install-Gitleaks {
  Write-Section "gitleaks (target >= 8.18.0)"
  $existing = Test-Binary "gitleaks"
  if ($existing) {
    $ver = (& gitleaks version 2>$null | Select-Object -First 1) -replace "^gitleaks version\s*", ""
    Write-Host "  already installed: $existing ($ver)" -ForegroundColor Green
    return $existing
  }
  if ($PreferredPkgManager -eq "winget" -or (-not $PreferredPkgManager -and (Get-Command winget -ErrorAction SilentlyContinue))) {
    Write-Host "  installing via 'winget install --id GitHub.gitleaks'..."
    & winget install --id GitHub.gitleaks --accept-package-agreements --accept-source-agreements
  } elseif ($PreferredPkgManager -eq "scoop" -or (-not $PreferredPkgManager -and (Get-Command scoop -ErrorAction SilentlyContinue))) {
    Write-Host "  installing via 'scoop install gitleaks'..."
    & scoop install gitleaks
  } elseif ($PreferredPkgManager -eq "choco" -or (-not $PreferredPkgManager -and (Get-Command choco -ErrorAction SilentlyContinue))) {
    Write-Host "  installing via 'choco install gitleaks'..."
    & choco install gitleaks -y
  } else {
    Write-Error "  no supported package manager found. Install one of: winget, scoop, choco - then re-run."
    return $null
  }
  return (Test-Binary "gitleaks")
}

function Install-Trivy {
  Write-Section "trivy (target >= 0.50.0)"
  $existing = Test-Binary "trivy"
  if ($existing) {
    $ver = (& trivy --version 2>$null | Select-Object -First 1) -replace "^Version:\s*", ""
    Write-Host "  already installed: $existing ($ver)" -ForegroundColor Green
    return $existing
  }
  if ($PreferredPkgManager -eq "winget" -or (-not $PreferredPkgManager -and (Get-Command winget -ErrorAction SilentlyContinue))) {
    Write-Host "  installing via 'winget install --id AquaSecurity.Trivy'..."
    & winget install --id AquaSecurity.Trivy --accept-package-agreements --accept-source-agreements
  } elseif ($PreferredPkgManager -eq "scoop" -or (-not $PreferredPkgManager -and (Get-Command scoop -ErrorAction SilentlyContinue))) {
    Write-Host "  installing via 'scoop install trivy'..."
    & scoop install trivy
  } elseif ($PreferredPkgManager -eq "choco" -or (-not $PreferredPkgManager -and (Get-Command choco -ErrorAction SilentlyContinue))) {
    Write-Host "  installing via 'choco install trivy'..."
    & choco install trivy -y
  } else {
    Write-Error "  no supported package manager found. Install one of: winget, scoop, choco - then re-run."
    return $null
  }
  return (Test-Binary "trivy")
}

# --- main -------------------------------------------------------------------

$results = [ordered]@{}

$results["semgrep"]  = (Install-Semgrep)
$results["gitleaks"] = (Install-Gitleaks)
$results["trivy"]    = (Install-Trivy)

Write-Section "summary"
$failed = @()
foreach ($k in $results.Keys) {
  $v = $results[$k]
  if ($v) {
    Write-Host ("  {0,-10} OK   {1}" -f $k, $v) -ForegroundColor Green
  } else {
    Write-Host ("  {0,-10} FAIL" -f $k) -ForegroundColor Red
    $failed += $k
  }
}
Write-Host ""
if ($failed.Count -gt 0) {
  Write-Error ("The following scanners could not be installed: $($failed -join ', ')")
  Write-Error "Re-run with -PreferredPkgManager <winget|scoop|choco> to force a manager, or install manually and re-run."
  exit 1
}
Write-Host "All scanners installed. You can now run: npx security-mcp-server (or node dist/index.js)" -ForegroundColor Green
exit 0
