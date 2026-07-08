#!/usr/bin/env bash
# setup-scanners.sh
# Installs the three external scanner CLIs that the security-mcp-server
# depends on (semgrep, gitleaks, trivy) on Linux and macOS.
#
# Idempotent: re-running is a no-op when already at the documented
# minimum versions. Always exits non-zero on any failure with a clear
# remediation hint written to stderr.
#
# Usage:
#   ./scripts/setup-scanners.sh
#
# Environment overrides:
#   PREFERRED_PKG_MANAGER=brew|apt|pacman   (default: auto)
#   SEMGREP_VERSION=1.95.0                  (default)
#   GITLEAKS_VERSION=8.18.4                 (default)
#   TRIVY_VERSION=0.50.1                    (default)
#
# Exit codes:
#   0  All three scanners installed and on PATH.
#   1  At least one scanner could not be installed.
#   2  Required prerequisite missing (e.g. no supported package manager).

set -euo pipefail

# --- Configuration ---------------------------------------------------------

SEMGREP_VERSION="${SEMGREP_VERSION:-1.95.0}"
GITLEAKS_VERSION="${GITLEAKS_VERSION:-8.18.4}"
TRIVY_VERSION="${TRIVY_VERSION:-0.50.1}"
PREFERRED_PKG_MANAGER="${PREFERRED_PKG_MANAGER:-auto}"

# --- Logging helpers -------------------------------------------------------

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[0;33m'; NC='\033[0m'

log()  { printf "%b==> %s%b\n" "$CYAN" "$*" "$NC" >&2; }
ok()   { printf "%b  OK    %s%b\n" "$GREEN" "$*" "$NC" >&2; }
fail() { printf "%b  FAIL  %s%b\n" "$RED" "$*" "$NC" >&2; }
warn() { printf "%b  WARN  %s%b\n" "$YELLOW" "$*" "$NC" >&2; }

# --- OS detection ----------------------------------------------------------

OS_FAMILY="unknown"
PM=""

if [[ "${OSTYPE:-}" == "darwin"* ]]; then
  OS_FAMILY="macos"
  if command -v brew >/dev/null 2>&1; then PM="brew"; fi
elif [[ -f /etc/os-release ]]; then
  . /etc/os-release
  case "${ID:-}" in
    ubuntu|debian|pop|elementary|linuxmint)
      OS_FAMILY="debian"
      PM="apt"
      ;;
    rhel|centos|rocky|almalinux|fedora|amazon)
      OS_FAMILY="rhel"
      PM=$(command -v dnf >/dev/null 2>&1 && echo dnf || echo yum)
      ;;
    arch|manjaro|endeavouros)
      OS_FAMILY="arch"
      PM="pacman"
      ;;
    *)
      OS_FAMILY="linux"
      PM=""
      ;;
  esac
fi

if [[ -z "${PM}" ]] && command -v brew >/dev/null 2>&1; then
  PM="brew"
fi

if [[ "${PREFERRED_PKG_MANAGER}" != "auto" ]]; then
  PM="${PREFERRED_PKG_MANAGER}"
fi

if [[ -z "${PM}" ]]; then
  fail "Could not detect a supported package manager."
  fail "Install Homebrew (https://brew.sh) or your distro's package manager and re-run."
  exit 2
fi

log "Detected OS family: ${OS_FAMILY}; package manager: ${PM}"

# --- Per-scanner installers -----------------------------------------------

detect_installed() {
  # Returns the resolved path on success, "" on failure.
  local name="$1"
  command -v "${name}" 2>/dev/null || true
}

print_version() {
  # Echoes a single-line version string, or "unknown".
  local bin="$1"
  "${bin}" --version 2>/dev/null | head -n1 || echo "unknown"
}

install_semgrep() {
  log "semgrep (target >= 1.40.0)"
  local existing
  existing="$(detect_installed semgrep || true)"
  if [[ -n "${existing}" ]]; then
    ok "already installed: ${existing} ($(print_version "${existing}"))"
    echo "${existing}"
    return 0
  fi

  case "${PM}" in
    brew)
      brew install semgrep
      ;;
    apt)
      # `semgrep` is a Python package; we install pipx and use it for a
      # clean user-level install that won't fight with system Python.
      if command -v pipx >/dev/null 2>&1; then
        pipx install "semgrep>=${SEMGREP_VERSION}"
      else
        warn "pipx not found; falling back to 'pip install --user'"
        python3 -m pip install --user "semgrep>=${SEMGREP_VERSION}"
      fi
      ;;
    dnf|yum)
      # semgrep is not packaged for RHEL/Fedora; install via pipx/pip.
      if command -v pipx >/dev/null 2>&1; then
        pipx install "semgrep>=${SEMGREP_VERSION}"
      else
        python3 -m pip install --user "semgrep>=${SEMGREP_VERSION}"
      fi
      ;;
    pacman)
      # AUR package `semgrep` exists but requires an AUR helper.
      if command -v yay >/dev/null 2>&1; then
        yay -S --noconfirm semgrep
      elif command -v paru >/dev/null 2>&1; then
        paru -S --noconfirm semgrep
      else
        fail "Install 'yay' or 'paru' for AUR access, then re-run."
        return 1
      fi
      ;;
  esac
  local installed
  installed="$(detect_installed semgrep || true)"
  if [[ -z "${installed}" ]]; then
    fail "semgrep install completed but 'semgrep' is still not on PATH."
    fail "If you used 'pip install --user', add ~/.local/bin to PATH and re-run this script."
    return 1
  fi
  ok "installed: ${installed} ($(print_version "${installed}"))"
  echo "${installed}"
}

install_gitleaks() {
  log "gitleaks (target >= 8.18.0)"
  local existing
  existing="$(detect_installed gitleaks || true)"
  if [[ -n "${existing}" ]]; then
    ok "already installed: ${existing} ($(print_version "${existing}"))"
    echo "${existing}"
    return 0
  fi

  case "${PM}" in
    brew)
      brew install gitleaks
      ;;
    apt)
      warn "gitleaks is not in the standard apt repos on most distros; downloading the GitHub release tarball."
      local arch
      arch="$(uname -m)"
      case "${arch}" in
        x86_64) arch="x86_64" ;;
        aarch64|arm64) arch="arm64" ;;
        *) fail "Unsupported arch: ${arch}"; return 1 ;;
      esac
      local url="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${arch}.tar.gz"
      local tmpdir
      tmpdir="$(mktemp -d)"
      curl -fsSL "${url}" -o "${tmpdir}/gitleaks.tgz"
      tar -xzf "${tmpdir}/gitleaks.tgz" -C "${tmpdir}" gitleaks
      sudo install -m 0755 "${tmpdir}/gitleaks" /usr/local/bin/gitleaks
      rm -rf "${tmpdir}"
      ;;
    dnf|yum)
      cat <<'EOF' | sudo tee /etc/yum.repos.d/gitleaks.repo >/dev/null
[gitleaks]
name=Gitleaks repository
baseurl=https://rpm.gitleaks.io/
enabled=1
gpgcheck=0
EOF
      sudo "${PM}" install -y gitleaks
      ;;
    pacman)
      if command -v yay >/dev/null 2>&1; then
        yay -S --noconfirm gitleaks
      elif command -v paru >/dev/null 2>&1; then
        paru -S --noconfirm gitleaks
      else
        fail "Install 'yay' or 'paru' for AUR access, then re-run."
        return 1
      fi
      ;;
  esac
  local installed
  installed="$(detect_installed gitleaks || true)"
  if [[ -z "${installed}" ]]; then
    fail "gitleaks install completed but 'gitleaks' is still not on PATH."
    return 1
  fi
  ok "installed: ${installed} ($(print_version "${installed}"))"
  echo "${installed}"
}

install_trivy() {
  log "trivy (target >= 0.50.0)"
  local existing
  existing="$(detect_installed trivy || true)"
  if [[ -n "${existing}" ]]; then
    ok "already installed: ${existing} ($(print_version "${existing}"))"
    echo "${existing}"
    return 0
  fi

  case "${PM}" in
    brew)
      brew install trivy
      ;;
    apt)
      sudo apt-get install -y wget apt-transport-https gnupg lsb-release
      wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | \
        sudo gpg --dearmor -o /usr/share/keyrings/trivy.gpg
      echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | \
        sudo tee /etc/apt/sources.list.d/trivy.list >/dev/null
      sudo apt-get update
      sudo apt-get install -y trivy
      ;;
    dnf|yum)
      cat <<'EOF' | sudo tee /etc/yum.repos.d/trivy.repo >/dev/null
[trivy]
name=Trivy repository
baseurl=https://aquasecurity.github.io/trivy-repo/rpm/releases/$basearch/
enabled=1
gpgcheck=0
EOF
      sudo "${PM}" install -y trivy
      ;;
    pacman)
      if command -v yay >/dev/null 2>&1; then
        yay -S --noconfirm trivy
      elif command -v paru >/dev/null 2>&1; then
        paru -S --noconfirm trivy
      else
        fail "Install 'yay' or 'paru' for AUR access, then re-run."
        return 1
      fi
      ;;
  esac
  local installed
  installed="$(detect_installed trivy || true)"
  if [[ -z "${installed}" ]]; then
    fail "trivy install completed but 'trivy' is still not on PATH."
    return 1
  fi
  ok "installed: ${installed} ($(print_version "${installed}"))"
  echo "${installed}"
}

# --- main ------------------------------------------------------------------

declare -A RESULTS
RESULTS[semgrep]=""
RESULTS[gitleaks]=""
RESULTS[trivy]=""

if ! RESULTS[semgrep]="$(install_semgrep)"; then RESULTS[semgrep]=""; fi
if ! RESULTS[gitleaks]="$(install_gitleaks)"; then RESULTS[gitleaks]=""; fi
if ! RESULTS[trivy]="$(install_trivy)"; then RESULTS[trivy]=""; fi

log "summary"
failed=()
for k in semgrep gitleaks trivy; do
  v="${RESULTS[$k]}"
  if [[ -n "${v}" ]]; then
    ok "${k}: ${v}"
  else
    fail "${k}: install failed"
    failed+=("${k}")
  fi
done

if [[ ${#failed[@]} -gt 0 ]]; then
  fail "The following scanners could not be installed: ${failed[*]}"
  fail "Re-run with PREFERRED_PKG_MANAGER=<brew|apt|pacman> to force a manager, or install manually and re-run."
  exit 1
fi

ok "All scanners installed. You can now run: npx security-mcp-server (or node dist/index.js)"
exit 0
