import { existsSync, statSync } from "node:fs";
import { dirname, isAbsolute, normalize, relative, resolve, sep } from "node:path";

/** Walk up from `startDir` until a `.git` entry is found. */
export function resolveRepoRoot(startDir: string): string {
  let current = resolve(startDir);
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

/** Thrown when no .git entry can be found above the start directory. */
export class RepoRootNotFoundError extends Error {
  readonly code = "repo_root_not_found";
  constructor(public readonly startDir: string) {
    super(`No .git directory found above ${startDir}`);
    this.name = "RepoRootNotFoundError";
  }
}

/** Thrown when a candidate path resolves outside the repo root. */
export class PathEscapeError extends Error {
  readonly code = "path_escape";
  constructor(public readonly candidate: string, public readonly repoRoot: string) {
    super(`Path '${candidate}' resolves outside repo root '${repoRoot}'`);
    this.name = "PathEscapeError";
  }
}

/** Resolve `candidate` and assert it lies inside `repoRoot`. */
export function assertInsideRepo(repoRoot: string, candidate: string): string {
  const absRepo = normalize(resolve(repoRoot)) + sep;
  const abs = normalize(isAbsolute(candidate) ? candidate : resolve(repoRoot, candidate));
  if (abs !== normalize(resolve(repoRoot)) && !abs.startsWith(absRepo)) {
    throw new PathEscapeError(candidate, repoRoot);
  }
  return abs;
}

/** Equivalent to `path.join(repoRoot, ...parts)` after sandboxing. */
export function safeJoin(repoRoot: string, ...parts: string[]): string {
  return assertInsideRepo(repoRoot, resolve(repoRoot, ...parts));
}

/** Compute the repo-relative path for a file inside the repo. */
export function relativeToRepo(repoRoot: string, absPath: string): string {
  const rel = relative(repoRoot, absPath);
  if (rel.startsWith(".") && rel !== ".") return rel.replace(/^\.\//, "");
  return rel;
}
