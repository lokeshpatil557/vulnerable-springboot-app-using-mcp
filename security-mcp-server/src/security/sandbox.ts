/**
 * Process-level sandbox. This is *defence-in-depth*, not a real isolation
 * boundary — a determined attacker with code execution can still escape.
 * Use OS-level isolation (containers, gVisor, nsjail) for stronger
 * guarantees. Within Node we:
 *   - Pin CWD to the repo root for every child process.
 *   - Drop dangerous env vars from child env (GIT_ASKPASS, SSH_*, etc.).
 *   - Reject tools from being passed absolute paths outside the repo.
 */

import { resolve, isAbsolute } from "node:path";

/** Env keys that, if present in the parent, should NOT be inherited by scanners. */
const STRIPPED_ENV_KEYS = [
  "SSH_AUTH_SOCK",
  "SSH_AGENT_PID",
  "GIT_ASKPASS",
  "GIT_TERMINAL_PROMPT",
  "PYTHONSTARTUP",
  "NODE_OPTIONS",
  "NODE_PATH",
  "ELECTRON_RUN_AS_NODE",
];

/** Build a child env that drops dangerous keys from the parent env. */
export function safeChildEnv(overrides: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  const out: NodeJS.ProcessEnv = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (STRIPPED_ENV_KEYS.includes(k)) continue;
    out[k] = v;
  }
  for (const [k, v] of Object.entries(overrides)) {
    if (v === undefined) continue;
    out[k] = v;
  }
  return out;
}

/** Resolve a path inside the sandbox root, throwing if it escapes. */
export function sandboxResolve(root: string, candidate: string): string {
  const abs = isAbsolute(candidate) ? candidate : resolve(root, candidate);
  if (abs !== root && !abs.startsWith(root + "/") && !abs.startsWith(root + "\\")) {
    throw new Error(`sandbox: path '${candidate}' is outside sandbox root`);
  }
  return abs;
}

/** A wrapped child-process spawn config that always pins CWD + uses safe env. */
export interface SandboxExec {
  cwd: string;
  env: NodeJS.ProcessEnv;
}

export function sandboxForRepo(repoRoot: string, extraEnv: NodeJS.ProcessEnv = {}): SandboxExec {
  return {
    cwd: repoRoot,
    env: safeChildEnv(extraEnv),
  };
}
