import { exec } from "./exec.js";

export interface GitStatus {
  isRepo: boolean;
  currentBranch: string | null;
  headCommit: string | null;
  repoRoot: string | null;
  isDirty: boolean;
}

export interface GitBlob {
  path: string;
  content: string;
}

/** Run a git command and capture stdout, returning "" on error. */
export async function git(args: string[], cwd: string): Promise<string> {
  const res = await exec("git", args, { cwd, timeoutMs: 30_000 });
  if (res.exitCode !== 0) return "";
  return res.stdout.trim();
}

/** Resolve the repository root (absolute path) or null if not a git repo. */
export async function gitRevParseShowToplevel(cwd: string): Promise<string | null> {
  const out = await git(["rev-parse", "--show-toplevel"], cwd);
  return out.length > 0 ? out : null;
}

/** Get the current branch name, or null if detached HEAD / not a repo. */
export async function gitCurrentBranch(cwd: string): Promise<string | null> {
  const out = await git(["rev-parse", "--abbrev-ref", "HEAD"], cwd);
  return out.length > 0 ? out : null;
}

/** Get the current HEAD commit SHA (short). */
export async function gitHeadCommit(cwd: string): Promise<string | null> {
  const out = await git(["rev-parse", "--short", "HEAD"], cwd);
  return out.length > 0 ? out : null;
}

/** Detect whether the working tree is dirty (uncommitted changes). */
export async function gitIsDirty(cwd: string): Promise<boolean> {
  const out = await git(["status", "--porcelain"], cwd);
  return out.length > 0;
}

/** Compose a full GitStatus snapshot for a directory. */
export async function gitStatus(cwd: string): Promise<GitStatus> {
  const [repoRoot, branch, head, dirty] = await Promise.all([
    gitRevParseShowToplevel(cwd),
    gitCurrentBranch(cwd),
    gitHeadCommit(cwd),
    gitIsDirty(cwd),
  ]);
  return {
    isRepo: repoRoot !== null,
    currentBranch: branch,
    headCommit: head,
    repoRoot,
    isDirty: dirty,
  };
}

/** Read a file at HEAD (returns "" on missing). */
export async function gitShowHead(path: string, cwd: string): Promise<string> {
  const out = await git(["show", `HEAD:${path}`], cwd);
  return out;
}

/**
 * Produce a unified diff for the working tree vs HEAD. Empty string if clean.
 */
export async function gitDiff(cwd: string, filePath?: string): Promise<string> {
  const args = ["diff", "--no-color", "--no-ext-diff"];
  if (filePath) args.push("--", filePath);
  const res = await exec("git", args, { cwd, timeoutMs: 60_000 });
  if (res.exitCode !== 0) return "";
  return res.stdout;
}
