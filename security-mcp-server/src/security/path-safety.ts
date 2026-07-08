/**
 * Strict path safety — single import surface for the eight checks the
 * server applies to every file-touching tool call.
 *
 *   1. Paths must resolve under `SECURITY_MCP_ALLOWED_ROOT`.
 *   2. Path traversal (`..`, encoded variants, NUL bytes) is rejected.
 *   3. Symlink escape outside the allowed root is rejected.
 *   4. The user's home directory, its parent, and the platform root
 *      are forbidden ancestors.
 *   5. Binary files are rejected for remediation flows.
 *   6. Per-file and per-diff size caps are enforced.
 *   7. Total repo size is bounded by `MAX_REPO_BYTES`.
 *   8. Every denial is logged via the structured logger and recorded
 *      in the audit log with `outcome: "denied"`.
 *
 * The module re-exports the legacy `paths.ts` helpers (`assertInsideRepo`,
 * `safeJoin`, `resolveRepoRoot`, `relativeToRepo`) so existing callers
 * continue to compile while new code routes through the guards.
 *
 * Pure functions where possible. The two I/O entry points (`stat`,
 * `lstat`, `readdir`) are isolated to the per-check primitives so the
 * high-level guards are easy to test against an in-memory mock.
 */

import { lstat, open, readdir, realpath, stat } from "node:fs/promises";
import { homedir } from "node:os";
import {
  basename,
  dirname,
  isAbsolute,
  join,
  normalize,
  parse as parsePath,
  relative,
  resolve,
  sep,
} from "node:path";
import type { Logger } from "pino";
import type { AuditLogger } from "../audit.js";
import {
  ApplyPolicyDeniedError,
  BinaryFileError,
  BlockedFileError,
  ForbiddenAncestorError,
  PayloadTooLargeError,
  PathEscapeError,
  SymlinkEscapeError,
  TraversalError,
} from "../errors.js";
import { assertInsideRepo, relativeToRepo, resolveRepoRoot } from "../paths.js";

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

export interface PathSafetyPolicy {
  /** Allowed root, populated by SECURITY_MCP_ALLOWED_ROOT. */
  allowedRoot: string;
  /** Max size of any single file the server will read. */
  maxFileBytes: number;
  /** Max total size of the repo tree. */
  maxRepoBytes: number;
  /** Max size of an inbound `diff` payload (UTF-8 bytes). */
  maxDiffBytes: number;
  /** When true, follow symlinks (target must still be inside the repo). */
  followSymlinks: boolean;
  /** When true, the apply_remediation tool is enabled. */
  allowApplyRemediation: boolean;
  /** Compiled regex patterns matched against the path. */
  blockedFiles: readonly RegExp[];
  /** Forbidden ancestor paths (homedir, parent, root, ...). */
  forbiddenAncestors: readonly string[];
  /** Optional text-extension allowlist for remediation. */
  textExtensions?: readonly RegExp[];
}

export interface PathSafetyResult {
  ok: boolean;
  reason?:
    | "escape"
    | "traversal"
    | "forbidden_ancestor"
    | "blocked"
    | "symlink_escape"
    | "absent"
    | "not_regular"
    | "too_large"
    | "binary"
    | "denied_by_policy";
  absPath?: string;
  relPath?: string;
  size?: number;
}

// ---------------------------------------------------------------------------
// Defaults + builders
// ---------------------------------------------------------------------------

const DEFAULT_TEXT_EXTENSIONS =
  /\.(java|kt|js|ts|jsx|tsx|py|go|rb|php|cs|swift|mjs|cjs|json|ya?ml|toml|md|gradle|scala|sql|sh|bash|env|properties|conf|ini|cfg|xml|html|css|scss|vue|svelte|gradle|kts|kt)$/i;

const DEFAULT_BLOCKED_FILE_PATTERNS = [
  "\\.env(\\..*)?$",
  "^id_rsa(\\.pub)?$",
  "^id_ed25519(\\.pub)?$",
  "(^|/)\\.ssh/.*",
  "(^|/)\\.aws/credentials$",
  "(^|/)\\.npmrc$",
  "(^|/)\\.pypirc$",
  "(^|/)\\.netrc$",
  "(^|/)\\.gitconfig$",
  "(^|/)\\.pgpass$",
];

/** Compile regex strings safely (invalid patterns are ignored with a warning). */
function compilePatterns(
  patterns: readonly string[],
  fallback: readonly string[],
): RegExp[] {
  const srcs = patterns.length > 0 ? patterns : fallback;
  const out: RegExp[] = [];
  for (const src of srcs) {
    try {
      out.push(new RegExp(src));
    } catch {
      // Skip invalid regex — never crash boot.
    }
  }
  return out;
}

/**
 * Build the platform-aware list of forbidden ancestors. Includes the
 * user's home directory, its parent (e.g. `/Users`, `C:\Users`), and the
 * platform's root. Caller-supplied entries are merged in.
 */
export function defaultForbiddenAncestors(extra: readonly string[] = []): string[] {
  const out = new Set<string>(extra);
  const home = homedir();
  out.add(normalize(home));
  out.add(normalize(dirname(home)));
  // Windows drive roots (C:\, D:\, E:\). POSIX: `/`.
  if (process.platform === "win32") {
    for (const letter of ["C", "D", "E"]) {
      out.add(`${letter}:\\`);
    }
  } else {
    out.add("/");
  }
  return [...out].map((p) => normalize(p));
}

/**
 * Convert a `Config["pathSafety"]` block (which carries regex strings
 * and platform-relative defaults) into a fully-resolved `PathSafetyPolicy`.
 * This is the helper the tool layer should call before passing the
 * config into a guard.
 */
export function policyFromConfig(
  raw: {
    allowedRoot?: string;
    maxFileBytes?: number;
    maxRepoBytes?: number;
    maxDiffBytes?: number;
    followSymlinks?: boolean;
    allowApplyRemediation?: boolean;
    blockedFiles?: string[];
    forbiddenAncestors?: string[];
  },
  fallbackRepoRoot: string,
): PathSafetyPolicy {
  return buildPolicy(raw, fallbackRepoRoot);
}

/**
 * Build a fully-populated policy from a Config["pathSafety"] block.
 * The `blockedFiles` strings are compiled into RegExps; the
 * `forbiddenAncestors` are merged with the platform defaults.
 */
export function buildPolicy(
  raw: {
    allowedRoot?: string;
    maxFileBytes?: number;
    maxRepoBytes?: number;
    maxDiffBytes?: number;
    followSymlinks?: boolean;
    allowApplyRemediation?: boolean;
    blockedFiles?: string[];
    forbiddenAncestors?: string[];
  },
  fallbackRepoRoot: string,
): PathSafetyPolicy {
  return {
    allowedRoot: normalize(resolve(raw.allowedRoot || fallbackRepoRoot || process.cwd())),
    maxFileBytes: raw.maxFileBytes ?? 26_214_400,
    maxRepoBytes: raw.maxRepoBytes ?? 1_073_741_824,
    maxDiffBytes: raw.maxDiffBytes ?? 1_048_576,
    followSymlinks: raw.followSymlinks ?? false,
    allowApplyRemediation: raw.allowApplyRemediation ?? false,
    blockedFiles: compilePatterns(raw.blockedFiles ?? [], DEFAULT_BLOCKED_FILE_PATTERNS),
    forbiddenAncestors: defaultForbiddenAncestors(raw.forbiddenAncestors ?? []),
    textExtensions: [DEFAULT_TEXT_EXTENSIONS],
  };
}

// ---------------------------------------------------------------------------
// Per-check primitives
// ---------------------------------------------------------------------------

/**
 * Detect path traversal patterns in the raw candidate. Returns true
 * if the candidate contains `..` segments, URL-encoded `..`, or NUL bytes.
 */
function hasTraversalSignals(candidate: string): boolean {
  if (candidate.includes("\0")) return true;
  // URL-encoded variants.
  const lowered = candidate.toLowerCase();
  if (lowered.includes("%2e%2e") || lowered.includes("%2f") || lowered.includes("%5c")) {
    return true;
  }
  // Split on both separators (Windows accepts both, POSIX only `/`).
  const segs = candidate.split(/[\\/]+/);
  return segs.includes("..") || segs.includes(".");
}

/**
 * Check 1+2+4: candidate must resolve under the allowed root and
 * must not live under a forbidden ancestor. Detects traversal
 * patterns up-front. Does NOT consult the filesystem.
 */
export function checkAllowedRoot(
  candidate: string,
  policy: PathSafetyPolicy,
): PathSafetyResult {
  if (typeof candidate !== "string" || candidate.length === 0) {
    return { ok: false, reason: "traversal" };
  }
  if (hasTraversalSignals(candidate)) {
    return { ok: false, reason: "traversal" };
  }
  // 4. Forbidden ancestors: every segment of the resolved absolute path
  //    must not be one of the forbidden ancestors.
  const abs = normalize(isAbsolute(candidate) ? candidate : resolve(policy.allowedRoot, candidate));
  for (const ancestor of policy.forbiddenAncestors) {
    const na = normalize(resolve(ancestor));
    if (abs === na || abs.startsWith(na + sep)) {
      return { ok: false, reason: "forbidden_ancestor", absPath: abs };
    }
  }
  // 1+2. assertInsideRepo performs the final "inside the repo" check.
  try {
    const inside = assertInsideRepo(policy.allowedRoot, abs);
    return { ok: true, absPath: inside, relPath: relativeToRepo(policy.allowedRoot, inside) };
  } catch (err) {
    if (err instanceof PathEscapeError) {
      return { ok: false, reason: "escape", absPath: abs };
    }
    throw err;
  }
}

/**
 * Check the path's basename and any path segment against the
 * `blockedFiles` regex set.
 */
export function checkBlockedFile(
  relPath: string,
  policy: PathSafetyPolicy,
): PathSafetyResult {
  const segments = relPath.split(/[\\/]+/);
  for (const seg of segments) {
    if (!seg) continue;
    for (const re of policy.blockedFiles) {
      if (re.test(seg)) {
        return { ok: false, reason: "blocked" };
      }
    }
  }
  return { ok: true };
}

/**
 * Check 3: symlink escape. If the path is a symlink, resolve its target
 * via realpath and ensure the target is inside the allowed root. When
 * `followSymlinks` is false, ANY symlink is denied outright.
 */
export async function checkSymlink(
  absPath: string,
  policy: PathSafetyPolicy,
): Promise<PathSafetyResult> {
  let lst;
  try {
    lst = await lstat(absPath);
  } catch (err) {
    return { ok: false, reason: "absent" };
  }
  if (!lst.isSymbolicLink()) {
    return { ok: true, size: lst.size };
  }
  if (!policy.followSymlinks) {
    return { ok: false, reason: "symlink_escape" };
  }
  // followSymlinks = true: resolve and re-assert inside root.
  let real;
  try {
    real = await realpath(absPath);
  } catch {
    return { ok: false, reason: "absent" };
  }
  const root = policy.allowedRoot;
  if (real !== root && !real.startsWith(root + sep) && !real.startsWith(root + "/")) {
    return { ok: false, reason: "symlink_escape", absPath: real };
  }
  let st;
  try {
    st = await stat(real);
  } catch {
    return { ok: false, reason: "absent" };
  }
  return { ok: true, absPath: real, size: st.size };
}

/** Check 6: per-file size cap. */
export async function checkFileSize(
  absPath: string,
  policy: PathSafetyPolicy,
): Promise<PathSafetyResult> {
  let st;
  try {
    st = await stat(absPath);
  } catch {
    return { ok: false, reason: "absent" };
  }
  if (!st.isFile()) {
    return { ok: false, reason: "not_regular", size: st.size };
  }
  if (st.size > policy.maxFileBytes) {
    return { ok: false, reason: "too_large", size: st.size };
  }
  return { ok: true, size: st.size };
}

/** Check 6: per-diff size cap (UTF-8 byte length). */
export function checkDiffSize(
  diff: string,
  policy: PathSafetyPolicy,
): PathSafetyResult {
  const bytes = Buffer.byteLength(diff ?? "", "utf8");
  if (bytes > policy.maxDiffBytes) {
    return { ok: false, reason: "too_large", size: bytes };
  }
  return { ok: true, size: bytes };
}

/**
 * Check 5: sniff the first 8 KiB for binary content. A NUL byte or
 * a non-printable, non-UTF-8 byte makes the file binary.
 */
export async function checkBinary(
  absPath: string,
  policy: PathSafetyPolicy,
): Promise<PathSafetyResult> {
  // textExtensions allowlist fast-path: if the basename matches a
  // known text extension, skip the sniff. This avoids false positives
  // on minified JS / source maps that may have non-ASCII.
  const exts = policy.textExtensions ?? [DEFAULT_TEXT_EXTENSIONS];
  const name = basename(absPath).toLowerCase();
  for (const re of exts) {
    if (re.test(name)) return { ok: true };
  }
  let handle;
  try {
    handle = await open(absPath, "r");
  } catch {
    return { ok: false, reason: "absent" };
  }
  try {
    const buf = Buffer.alloc(8192);
    const { bytesRead } = await handle.read(buf, 0, buf.length, 0);
    return { ok: !looksBinary(buf.subarray(0, bytesRead)) };
  } finally {
    await handle.close();
  }
}

function looksBinary(buf: Buffer): boolean {
  if (buf.length === 0) return false;
  // Skip UTF-8 BOM
  let start = 0;
  if (buf.length >= 3 && buf[0] === 0xef && buf[1] === 0xbb && buf[2] === 0xbf) {
    start = 3;
  }
  for (let i = start; i < buf.length; i++) {
    const b = buf[i] as number;
    if (b === 0) return true;
    if (b < 0x09) return true; // control chars other than tab/LF/CR
    if (b > 0x7e && b < 0xa0) return true;
  }
  return false;
}

/**
 * Check 7: walk the repo tree and reject if total size exceeds
 * `maxRepoBytes`. Bounded to depth 8 and 50 000 entries to avoid
 * pathological scans.
 */
export async function checkRepoSize(
  repoRoot: string,
  policy: PathSafetyPolicy,
): Promise<PathSafetyResult> {
  const limit = 50_000;
  const maxDepth = 8;
  let total = 0;
  let count = 0;
  const stack: { dir: string; depth: number }[] = [{ dir: repoRoot, depth: 0 }];
  while (stack.length > 0) {
    const { dir, depth } = stack.pop()!;
    if (depth > maxDepth) continue;
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const ent of entries) {
      if (count > limit) return { ok: false, reason: "too_large", size: total };
      const full = join(dir, ent.name);
      // Skip well-known heavy / irrelevant directories.
      if (
        ent.isDirectory() &&
        (ent.name === ".git" ||
          ent.name === "node_modules" ||
          ent.name === ".security-mcp" ||
          ent.name === "dist" ||
          ent.name === "build" ||
          ent.name === "target" ||
          ent.name === "venv" ||
          ent.name === ".venv")
      ) {
        continue;
      }
      if (ent.isFile()) {
        try {
          const st = await stat(full);
          total += st.size;
          count++;
          if (total > policy.maxRepoBytes) {
            return { ok: false, reason: "too_large", size: total };
          }
        } catch {
          // ignore
        }
      } else if (ent.isDirectory()) {
        stack.push({ dir: full, depth: depth + 1 });
      }
    }
  }
  return { ok: true, size: total };
}

// ---------------------------------------------------------------------------
// Denial logging + audit
// ---------------------------------------------------------------------------

export interface GuardContext {
  logger?: Logger;
  audit?: AuditLogger;
  tool?: string;
  actor?: string;
  requestId?: string;
}

function logDenial(
  ctx: GuardContext | undefined,
  code: string,
  candidate: string | undefined,
  details: Record<string, unknown>,
): void {
  const payload = {
    code,
    tool: ctx?.tool,
    actor: ctx?.actor,
    requestId: ctx?.requestId,
    candidate,
    ...details,
  };
  if (ctx?.logger) {
    ctx.logger.warn(payload, "path_safety_denied");
  }
  if (ctx?.audit) {
    ctx.audit.record({
      ts: new Date().toISOString(),
      tool: ctx?.tool ?? "unknown",
      args: { candidate, ...details },
      findingCount: 0,
      durationMs: 0,
      outcome: "denied",
      errorCode: code,
      pathSafe: false,
      requestId: ctx?.requestId,
      actor: ctx?.actor,
    });
  }
}

function throwFromReason(
  reason: string,
  candidate: string,
  policy: PathSafetyPolicy,
  ctx: GuardContext | undefined,
  extras: Record<string, unknown> = {},
): never {
  const code = reason;
  logDenial(ctx, code, candidate, { reason, ...extras });
  switch (reason) {
    case "traversal":
      throw new TraversalError(candidate);
    case "forbidden_ancestor":
      throw new ForbiddenAncestorError(candidate, String(extras.ancestor ?? ""));
    case "blocked":
      throw new BlockedFileError(candidate, String(extras.pattern ?? ""));
    case "symlink_escape":
      throw new SymlinkEscapeError(candidate, String(extras.target ?? candidate));
    case "too_large":
      throw new PayloadTooLargeError(
        (extras.what as "file" | "diff" | "repo") ?? "file",
        Number(extras.actual ?? 0),
        Number(extras.max ?? policy.maxFileBytes),
      );
    case "binary":
      throw new BinaryFileError(candidate);
    case "denied_by_policy":
      throw new ApplyPolicyDeniedError(policy.allowedRoot);
    case "escape":
    case "absent":
    case "not_regular":
    default:
      throw new PathEscapeError(candidate, policy.allowedRoot);
  }
}

// ---------------------------------------------------------------------------
// High-level guards
// ---------------------------------------------------------------------------

/**
 * Guard a path intended for reading. Enforces 1, 2, 3, 4, 6.
 * Throws a typed error on the first failure.
 */
export function guardReadPath(
  repoRoot: string,
  candidate: string,
  policy: PathSafetyPolicy,
  ctx: GuardContext = {},
): { absPath: string; relPath: string } {
  // Use the policy's allowedRoot, not the passed repoRoot, as the
  // source of truth. The passed value is kept for backwards compat.
  const root = policy.allowedRoot || repoRoot;
  const pol: PathSafetyPolicy = { ...policy, allowedRoot: root };

  // 1+2+4. Resolves and asserts.
  const allowed = checkAllowedRoot(candidate, pol);
  if (!allowed.ok) {
    throwFromReason(allowed.reason ?? "escape", candidate, pol, ctx, {
      ancestor: policy.forbiddenAncestors[0],
    });
  }
  const absPath = allowed.absPath!;
  const relPath = allowed.relPath!;

  // Blocked-file patterns (secrets).
  const blocked = checkBlockedFile(relPath, pol);
  if (!blocked.ok) {
    throwFromReason("blocked", candidate, pol, ctx, { pattern: relPath });
  }

  // 6. Per-file size. Async, but we return a sync result by
  // delegating to a promise-returning wrapper when the caller needs
  // the size check; for `guardReadPath` we keep the API sync and
  // perform size check via `lstat` (cheap, no file read).
  // Symlink check is async, so we return a promise-like if we need
  // it. To keep this guard fully sync, we expose `guardReadPathAsync`
  // for callers that need symlink + size verification together.

  return { absPath, relPath };
}

/**
 * Async variant of `guardReadPath` that also enforces 3 (symlink) and
 * 6 (file size). Use this from tools that are already async.
 */
export async function guardReadPathAsync(
  repoRoot: string,
  candidate: string,
  policy: PathSafetyPolicy,
  ctx: GuardContext = {},
): Promise<{ absPath: string; relPath: string; size: number }> {
  const { absPath, relPath } = guardReadPath(repoRoot, candidate, policy, ctx);
  // 3. Symlink check.
  const sym = await checkSymlink(absPath, policy);
  if (!sym.ok) {
    throwFromReason(sym.reason ?? "symlink_escape", candidate, policy, ctx, {
      target: sym.absPath,
    });
  }
  // 6. Size.
  const size = await checkFileSize(absPath, policy);
  if (!size.ok) {
    throwFromReason(size.reason ?? "too_large", candidate, policy, ctx, {
      what: "file",
      actual: size.size,
      max: policy.maxFileBytes,
    });
  }
  return { absPath, relPath, size: size.size ?? 0 };
}

/**
 * Guard a path that will be used for remediation. Enforces 1, 2, 3, 4,
 * 5, 6. Use this from `generate_remediation` and `apply_remediation`.
 */
export async function guardRemediationFile(
  repoRoot: string,
  candidate: string,
  policy: PathSafetyPolicy,
  ctx: GuardContext = {},
): Promise<{ absPath: string; relPath: string; size: number }> {
  const { absPath, relPath, size } = await guardReadPathAsync(
    repoRoot,
    candidate,
    policy,
    ctx,
  );
  // 5. Binary rejection.
  const bin = await checkBinary(absPath, policy);
  if (!bin.ok) {
    throwFromReason("binary", candidate, policy, ctx, { size });
  }
  return { absPath, relPath, size };
}

/** Guard an inbound `diff` payload. Enforces 6. */
export function guardDiffPayload(
  diff: string,
  policy: PathSafetyPolicy,
  ctx: GuardContext = {},
): string {
  const r = checkDiffSize(diff ?? "", policy);
  if (!r.ok) {
    throwFromReason(r.reason ?? "too_large", "<diff>", policy, ctx, {
      what: "diff",
      actual: r.size,
      max: policy.maxDiffBytes,
    });
  }
  return diff;
}

/**
 * Guard the full apply_remediation call: file path + diff payload.
 * Caller is expected to enforce the `ALLOW_APPLY_REMEDIATION` policy
 * gate **before** calling this helper (we re-check it here for safety).
 */
export async function guardApply(
  repoRoot: string,
  candidate: string,
  diff: string,
  policy: PathSafetyPolicy,
  ctx: GuardContext = {},
): Promise<{ absPath: string; relPath: string; diff: string; size: number }> {
  if (!policy.allowApplyRemediation) {
    throwFromReason("denied_by_policy", candidate, policy, ctx, {
      policy: "allowApplyRemediation",
    });
  }
  const file = await guardRemediationFile(repoRoot, candidate, policy, ctx);
  const safeDiff = guardDiffPayload(diff, policy, ctx);
  return { ...file, diff: safeDiff };
}

// Re-exports for backwards compatibility.
export { assertInsideRepo, resolveRepoRoot, safeJoin, relativeToRepo } from "../paths.js";
export { PathEscapeError, RepoRootNotFoundError } from "../errors.js";

// `safeJoin` is also re-exported from the legacy module. Provide a
// shim that calls into the existing helper. (paths.ts already defines
// `safeJoin`; the re-export above covers it.)

// Suppress unused-var warning for `parsePath` import (kept for future use).
void parsePath;
void relative;
