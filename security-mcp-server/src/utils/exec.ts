import { execa, type ExecaError, type Options } from "execa";
import { withTimeout } from "./file-utils.js";

export interface ExecOptions {
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  timeoutMs?: number;
  input?: string | null;
  /** When true, return raw stdout even on non-zero exit. */
  rejectOnError?: boolean;
  /** Hard cap on captured stdout/stderr. */
  maxBuffer?: number;
}

export interface ExecResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  durationMs: number;
  timedOut: boolean;
}

/**
 * Safe child-process execution. Always array-args (no shell). On timeout, the
 * process tree is killed via `withTimeout` + a best-effort SIGKILL fallback.
 */
export async function exec(
  command: string,
  args: string[] = [],
  options: ExecOptions = {},
): Promise<ExecResult> {
  const start = Date.now();
  const execaOpts: Options = {
    cwd: options.cwd,
    env: options.env ?? process.env,
    input: options.input ?? undefined,
    reject: false,
    maxBuffer: options.maxBuffer ?? 256 * 1024 * 1024,
    shell: false, // never interpolate
    windowsHide: true,
  };
  const timeoutMs = options.timeoutMs ?? 5 * 60_000;
  try {
    const child = execa(command, args, execaOpts);
    const res = await withTimeout(child, timeoutMs, command);
    return {
      exitCode: res.exitCode ?? -1,
      stdout: typeof res.stdout === "string" ? res.stdout : "",
      stderr: typeof res.stderr === "string" ? res.stderr : "",
      durationMs: Date.now() - start,
      timedOut: false,
    };
  } catch (err) {
    const e = err as ExecaError;
    const timedOut = e.timedOut === true || /timeout/i.test(String(err));
    return {
      exitCode: e.exitCode ?? -1,
      stdout: typeof e.stdout === "string" ? e.stdout : "",
      stderr: typeof e.stderr === "string" ? e.stderr : String(err),
      durationMs: Date.now() - start,
      timedOut,
    };
  }
}
