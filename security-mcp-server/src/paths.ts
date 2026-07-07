import { existsSync, statSync } from "node:fs";
import { dirname, isAbsolute, normalize, relative, resolve, sep } from "node:path";
import { RepoRootNotFoundError, PathEscapeError } from "./errors.js";

/**
 * Walk up from `startDir` until a `.git` entry (file or directory) is found.
 * Returns the directory containing the `.git` entry. Throws if none found.
 */
export function resolveRepoRoot(startDir: string): string {
  let current = resolve(startDir);
  // Hard cap to avoid infinite loops on misbehaving filesystems.
  for (let i = 0; i < 256; i++) {
    const candidate = resolve(current, ".git");
    if (gitEntryExists(candidate)) return current;
    const parent = dirname(current);
    if (parent === current) break;
    current = parent;
  }
  throw new RepoRootNotFoundError(startDir);
}

function gitEntryExists(p: string): boolean {
  if (!existsSync(p)) return false;
  try {
    const s = statSync(p);
    return s.isDirectory() || s.isFile();
  } catch {
    return false;
  }
}

/**
 * Resolve `candidate` and assert it lies inside `repoRoot`. Returns the
 * normalized absolute path. Throws `PathEscapeError` on escape.
 */
export function assertInsideRepo(repoRoot: string, candidate: string): string {
  const absRepo = normalize(resolve(repoRoot)) + sep;
  const abs = normalize(isAbsolute(candidate) ? candidate : resolve(repoRoot, candidate));
  // The trailing-sep trick: every inside path must begin with absRepo.
  if (abs !== normalize(resolve(repoRoot)) && !abs.startsWith(absRepo)) {
    throw new PathEscapeError(candidate, repoRoot);
  }
  return abs;
}

/** Safe path join: equivalent to `path.join(repoRoot, ...parts)` after sandboxing. */
export function safeJoin(repoRoot: string, ...parts: string[]): string {
  return assertInsideRepo(repoRoot, resolve(repoRoot, ...parts));
}

/** Compute the repo-relative path for a file inside the repo. */
export function relativeToRepo(repoRoot: string, absPath: string): string {
  const rel = relative(repoRoot, absPath);
  // `relative` returns "" for identical paths, "./foo" for some platforms.
  return rel.startsWith(".") && rel !== "." ? rel.replace(/^\.\//, "") : rel;
}
