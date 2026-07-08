#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Prefer the project-scoped `.mcp.json` at the monorepo root.
# See ../../README.md — Claude Code auto-registers the server for every
# teammate with no path editing required.
#
# Use THIS script only if you cannot commit a `.mcp.json` in the repo
# root (e.g. you run Claude Code against a directory you don't control).
# It registers the server in your *user-level* Claude Code config using
# the absolute path it computes from this script's own location, so it
# still works regardless of where you cloned the repo.
# ---------------------------------------------------------------------------

# Resolve the absolute path of this server, no matter where the script
# is invoked from.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DIST_ENTRY="$SERVER_DIR/dist/index.js"

if [[ ! -f "$DIST_ENTRY" ]]; then
  echo "error: $DIST_ENTRY not found." >&2
  echo "       run 'npm install && npm run build' inside $SERVER_DIR first." >&2
  exit 1
fi

# Local install (most common — points at the freshly-built dist):
claude mcp add security-mcp-server -- node "$DIST_ENTRY"

# With an explicit REPO_ROOT so the server always scans the same project,
# regardless of which directory Claude Code was started in:
REPO_ROOT="$SERVER_DIR/../sprint_boot_applications_demo_git"
claude mcp add security-mcp-server \
  --env REPO_ROOT="$REPO_ROOT" \
  --env LOG_LEVEL=info \
  --env SCAN_TIMEOUT_MS=600000 \
  -- node "$DIST_ENTRY"

# If you publish the package to npm and want to use npx:
# claude mcp add security-mcp-server -- npx -y security-mcp-server
