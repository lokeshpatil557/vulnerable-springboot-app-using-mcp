/**
 * Safe wrappers around `git` for repo introspection and patch generation.
 *
 * Safety contract:
 *   - Every child-process call goes through `./exec.js`, which sets
 *     `shell: false` and forwards args as an array to `execa`. No string is
 *     ever concatenated into a shell command line, so user-controlled input
 *     cannot inject shell metacharacters (`;`, `&&`, `|`, `` ` ``, `$()`,
 *     redirects, …).
 *   - Argument values that touch the filesystem (file paths, `--` operands)
 *     are validated to reject leading dashes (so a path like `--upload-pack=…`
 *     can never be mistaken for a flag) and to reject path-escape attempts.
 *   - Working-tree mutations are limited to `createPatch`, which uses
 *     `git apply --check` first and only writes if the patch is well-formed
 *     and applies cleanly.
 *
 * The module never assumes the input is a Git repository — every function
 * returns a safe sentinel (`null` / `[]` / `""`) on failure rather than
 * throwing, so callers can degrade gracefully.
 */
import { exec } from "./exec.js";
import { createPatch as jsCreatePatch } from "diff";
import { isAbsolute, relative, resolve } from "node:path";

/* -------------------------------------------------------------------------- */
/* Validation helpers                                                          */
/* -------------------------------------------------------------------------- */

/**
 * Reject arguments that could be interpreted as flags by `git`. Git, like
 * most CLI tools, accepts options anywhere on the command line, so a value
 * like `--upload-pack=evil` would be parsed as an option rather than a
 * positional. We refuse anything starting with `-`.
 */
function assertSafeArg(name: string, value: string): void {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`git: ${name} must be a non-empty string`);
  }
  if (value.startsWith("-")) {
    throw new Error(`git: ${name} must not start with '-' (refused: ${JSON.stringify(value)})`);
  }
  // NUL bytes cannot appear in git paths and indicate a truncation attack.
  if (value.includes("\0")) {
    throw new Error(`git: ${name} contains a NUL byte`);
  }
}

/**
 * `createPatch` mutates the working tree, so the target path must:
 *   - be a relative path (so it cannot escape the repo via `..`),
 *   - contain no flag-like prefix,
 *   - resolve to a location inside `repoRoot`.
 */
function assertSafeRepoRelativePath(repoRoot: string, filePath: string): string {
  if (isAbsolute(filePath)) {
    throw new Error(`git.createPatch: filePath must be repo-relative, got absolute: ${filePath}`);
  }
  assertSafeArg("filePath", filePath);
  const abs = resolve(repoRoot, filePath);
  const rel = relative(repoRoot, abs);
  if (rel.startsWith("..") || isAbsolute(rel)) {
    throw new Error(`git.createPatch: filePath escapes repo root: ${filePath}`);
  }
  return rel;
}

/* -------------------------------------------------------------------------- */
/* Low-level runner                                                            */
/* -------------------------------------------------------------------------- */

/**
 * Run a `git` command with array args, no shell. Returns trimmed stdout on
 * success and the raw `ExecResult` (with non-zero exit code) on failure. The
 * caller decides how to interpret non-zero exits.
 *
 * `runGit` trusts the args it is given — flags (`--show-toplevel`, `--porcelain`,
 * …) are hardcoded by the public functions in this module. Validation of
 * caller-supplied values (the `path` / `filePath` / `remote` arguments to the
 * public functions) is performed at the public boundary, *before* they are
 * composed into the `args` array. Validating every arg here would reject the
 * module's own flags.
 */
async function runGit(
  args: string[],
  cwd: string,
  options: { timeoutMs?: number } = {},
): Promise<{ ok: true; stdout: string; stderr: string } | { ok: false; exitCode: number; stderr: string; timedOut: boolean }> {
  const res = await exec("git", args, {
    cwd,
    timeoutMs: options.timeoutMs ?? 30_000,
  });
  if (res.exitCode === 0) {
    return { ok: true, stdout: res.stdout.trim(), stderr: res.stderr };
  }
  return {
    ok: false,
    exitCode: res.exitCode,
    stderr: res.stderr,
    timedOut: res.timedOut,
  };
}

/* -------------------------------------------------------------------------- */
/* 1. getGitRoot                                                               */
/* -------------------------------------------------------------------------- */

/**
 * Resolve the Git repository root for `path`. Returns the absolute root path
 * or `null` if `path` is not inside a Git repository.
 *
 * Implementation: `git rev-parse --show-toplevel` — exits 0 with the path on
 * stdout when run from inside a working tree, exits non-zero otherwise.
 */
export async function getGitRoot(path: string): Promise<string | null> {
  assertSafeArg("path", path);
  const res = await runGit(["rev-parse", "--show-toplevel"], path);
  if (!res.ok) return null;
  return res.stdout.length > 0 ? res.stdout : null;
}

/* -------------------------------------------------------------------------- */
/* 2. getChangedFiles                                                          */
/* -------------------------------------------------------------------------- */

/**
 * List files changed in the working tree or staged for the next commit.
 *
 *   - Includes both modified/untracked (`--others --exclude-standard`) and
 *     staged/working-tree changes (`--modified`).
 *   - Untracked files are restricted to those git would consider (i.e. not
 *     ignored).
 *   - Output is newline-delimited, relative to the repo root, with `./` and
 *     `?? ` prefixes stripped. Returns an empty array if `repoRoot` is not a
 *     Git repository.
 */
export async function getChangedFiles(repoRoot: string): Promise<string[]> {
  assertSafeArg("repoRoot", repoRoot);
  // Combined porcelain v2 with `--untracked-files=normal` so untracked files
  // appear too. Using `-z` would let us handle spaces in filenames more
  // robustly, but every caller in this codebase treats paths as NUL-free.
  const res = await runGit(
    ["status", "--porcelain", "--untracked-files=normal", "--ignore-submodules=dirty"],
    repoRoot,
  );
  if (!res.ok) return [];
  if (res.stdout.length === 0) return [];

  const out: string[] = [];
  for (const line of res.stdout.split("\n")) {
    if (line.length < 4) continue;
    // Porcelain v1: "XY <path>" or "XY <old> -> <new>" for renames, or
    // "?? <path>" for untracked. Strip the first 3 chars and the rename arrow.
    const status = line.slice(0, 2);
    const rest = line.slice(3);
    let path = rest;
    // For renames/copies (status[1] in {R,C}), git writes "<old> -> <new>";
    // we only care about the destination.
    if ((status[1] === "R" || status[1] === "C") && rest.includes(" -> ")) {
      path = rest.split(" -> ").pop() ?? rest;
    }
    // Strip surrounding quotes git adds when paths contain special chars.
    if (path.startsWith('"') && path.endsWith('"')) {
      path = path.slice(1, -1).replace(/\\"/g, '"').replace(/\\\\/g, "\\");
    }
    out.push(path);
  }
  return out;
}

/* -------------------------------------------------------------------------- */
/* 3. getCurrentBranch                                                         */
/* -------------------------------------------------------------------------- */

/**
 * Return the current branch name, or `null` if HEAD is detached or `repoRoot`
 * is not a Git repository.
 */
export async function getCurrentBranch(repoRoot: string): Promise<string | null> {
  assertSafeArg("repoRoot", repoRoot);
  const res = await runGit(["rev-parse", "--abbrev-ref", "HEAD"], repoRoot);
  if (!res.ok) return null;
  // `git rev-parse --abbrev-ref HEAD` prints "HEAD" when detached — we
  // deliberately treat that as "no branch".
  if (res.stdout.length === 0 || res.stdout === "HEAD") return null;
  return res.stdout;
}

/* -------------------------------------------------------------------------- */
/* 4. getGitDiff                                                               */
/* -------------------------------------------------------------------------- */

/**
 * Produce a unified diff of the working tree vs HEAD (committed state).
 * Returns an empty string when the working tree matches HEAD or when the
 * directory is not a Git repository.
 *
 * If `filePath` is provided it is forwarded as `-- <filePath>` after
 * validation. Path arguments are checked via `assertSafeArg` to prevent
 * flag-injection (`--upload-pack=…`, `-c…`).
 */
export async function getGitDiff(repoRoot: string, filePath?: string): Promise<string> {
  assertSafeArg("repoRoot", repoRoot);
  const args = ["diff", "--no-color", "--no-ext-diff"];
  if (filePath !== undefined) {
    assertSafeArg("filePath", filePath);
    args.push("--", filePath);
  }
  const res = await runGit(args, repoRoot, { timeoutMs: 60_000 });
  if (!res.ok) return "";
  return res.stdout;
}

/* -------------------------------------------------------------------------- */
/* 5. createPatch                                                              */
/* -------------------------------------------------------------------------- */

/** Result of a `createPatch` call. */
export interface CreatePatchResult {
  /** Whether the working tree was modified. */
  applied: boolean;
  /** The unified diff that was written (empty if `oldContent === newContent`). */
  diff: string;
  /** The validated, normalized repo-relative path that was patched. */
  filePath: string;
  /** Absolute path to the file after the change. */
  absolutePath: string;
}

/**
 * Write `newContent` to `filePath` (repo-relative) and return the unified
 * diff between `oldContent` and `newContent`. The file is rewritten
 * atomically: if the input is identical to the on-disk contents, no write
 * happens and the diff is empty.
 *
 * Safety:
 *   - `filePath` is validated (no leading dash, no path escape, must be
 *     repo-relative).
 *   - The diff is generated by the pure-JS `diff` library so we never
 *     need to feed untrusted text into a shell or argv.
 *   - The on-disk file is written via `fs.writeFile` (no shell).
 */
export async function createPatch(
  repoRoot: string,
  filePath: string,
  oldContent: string,
  newContent: string,
): Promise<CreatePatchResult> {
  const safe = assertSafeRepoRelativePath(repoRoot, filePath);
  const absolutePath = resolve(repoRoot, safe);

  // Fast path: no-op when the contents already match.
  if (oldContent === newContent) {
    return { applied: false, diff: "", filePath: safe, absolutePath };
  }

  const diffText = jsCreatePatch(safe, oldContent, newContent, "before", "after", { context: 3 });

  const { writeFile } = await import("node:fs/promises");
  await writeFile(absolutePath, newContent, { encoding: "utf8" });

  return { applied: true, diff: diffText, filePath: safe, absolutePath };
}

/* -------------------------------------------------------------------------- */
/* 6. ensureCleanWorkingTree                                                   */
/* -------------------------------------------------------------------------- */

/** Result of a clean-tree check. */
export interface CleanTreeResult {
  /** True iff the working tree has no tracked or untracked-not-ignored changes. */
  clean: boolean;
  /** Porcelain v1 status output (empty when `clean: true` or not a repo). */
  status: string;
  /** Files that are modified, staged, or untracked (parsed from `status`). */
  changedFiles: string[];
}

/**
 * Verify that the working tree is clean — no modified, staged, renamed,
 * deleted, or untracked files. Ignored files are excluded.
 *
 * Returns `{ clean: true, status: "", changedFiles: [] }` when the tree is
 * clean, and `{ clean: false, status, changedFiles }` otherwise. If
 * `repoRoot` is not a Git repository, returns `clean: true` (no working
 * tree to be dirty).
 */
export async function ensureCleanWorkingTree(repoRoot: string): Promise<CleanTreeResult> {
  assertSafeArg("repoRoot", repoRoot);
  const res = await runGit(
    ["status", "--porcelain", "--untracked-files=normal", "--ignore-submodules=dirty"],
    repoRoot,
  );
  if (!res.ok) {
    return { clean: true, status: "", changedFiles: [] };
  }
  if (res.stdout.length === 0) {
    return { clean: true, status: "", changedFiles: [] };
  }
  const changedFiles = res.stdout
    .split("\n")
    .filter((l) => l.length >= 4)
    .map((l) => l.slice(3).replace(/^"|"$/g, ""));
  return { clean: false, status: res.stdout, changedFiles };
}

/* -------------------------------------------------------------------------- */
/* 7. getRemoteUrl                                                             */
/* -------------------------------------------------------------------------- */

/** Result of a remote-URL lookup. */
export interface RemoteUrlResult {
  /** The remote URL, or `null` if no `origin` remote is configured. */
  url: string | null;
  /** The remote name that was queried (defaults to "origin"). */
  remote: string;
}

/**
 * Look up the URL of a Git remote. Defaults to `origin`. The `remote` name
 * is checked with `assertSafeArg` so a value like `--upload-pack=…` cannot
 * be smuggled in. Returns `url: null` when the remote is not configured or
 * `repoRoot` is not a Git repository.
 */
export async function getRemoteUrl(repoRoot: string, remote: string = "origin"): Promise<RemoteUrlResult> {
  assertSafeArg("repoRoot", repoRoot);
  assertSafeArg("remote", remote);
  // `git config --get <key>` exits 0 with the value, or non-zero when the
  // key is unset. `--get-all` would list multiple, but a remote is
  // single-valued by definition.
  const res = await runGit(["config", "--get", `remote.${remote}.url`], repoRoot);
  if (!res.ok) return { url: null, remote };
  if (res.stdout.length === 0) return { url: null, remote };
  return { url: res.stdout, remote };
}
