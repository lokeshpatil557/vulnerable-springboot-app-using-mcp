#!/usr/bin/env node
/**
 * run-setup.js — cross-platform wrapper around `setup-scanners.sh` /
 * `setup-scanners.ps1`. Invoked by `npm run setup:scanners` so that
 * the same command works on Linux, macOS, and Windows without the
 * developer needing to know the platform-specific script name.
 *
 * Behaviour:
 *   - On Windows: spawns `powershell -ExecutionPolicy Bypass -File
 *     scripts/setup-scanners.ps1` and propagates the exit code.
 *   - On every other platform: spawns `bash scripts/setup-scanners.sh`
 *     and propagates the exit code.
 *   - All child stdout/stderr stream through unchanged.
 */
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const isWin = process.platform === "win32";
const cmd = isWin ? "powershell.exe" : "bash";
const args = isWin
  ? [
      "-ExecutionPolicy",
      "Bypass",
      "-File",
      join(here, "setup-scanners.ps1"),
    ]
  : [join(here, "setup-scanners.sh")];

const child = spawn(cmd, args, { stdio: "inherit" });
child.on("error", (err) => {
  process.stderr.write(`security-mcp-server: failed to spawn ${cmd}: ${err.message}\n`);
  process.exit(2);
});
child.on("close", (code) => {
  process.exit(typeof code === "number" ? code : 1);
});
