#!/usr/bin/env bash
# Add security-mcp-server to Claude Code. Adjust the path to match your install.

# Local development (most common — points at the freshly-built dist):
claude mcp add security-mcp-server -- node "C:/Users/Lenovo/Downloads/security-mcp-server/dist/index.js"

# With an explicit REPO_ROOT so the server always scans the same project,
# regardless of which directory Claude Code was started in:
claude mcp add security-mcp-server \
  --env REPO_ROOT="C:/Users/Lenovo/Downloads/sprint_boot_applications_demo_git" \
  --env LOG_LEVEL=info \
  --env SCAN_TIMEOUT_MS=600000 \
  -- node "C:/Users/Lenovo/Downloads/security-mcp-server/dist/index.js"

# If you publish the package to npm and want to use npx:
# claude mcp add security-mcp-server -- npx -y security-mcp-server
