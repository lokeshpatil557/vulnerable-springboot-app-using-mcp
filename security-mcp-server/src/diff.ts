import { createPatch } from "diff";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { safeJoin } from "./paths.js";
import { sha256Hex } from "./util/hash.js";

/** Generate a unified diff for a single file change. */
export function generateUnifiedDiff(
  filePath: string,
  original: string,
  modified: string,
): string {
  return createPatch(filePath, original, modified, "before", "after", { context: 3 });
}

export interface ApplyResult {
  backupPath: string;
  sha256Before: string;
  writtenPath: string;
}

/**
 * Apply `modified` to `target` (must be inside `repoRoot`) after writing a
 * backup under `<repoRoot>/.security-mcp/backups/<iso-timestamp>/<rel-path>`.
 * Returns paths and pre-image hash for downstream verification.
 */
export async function applyWithBackup(
  repoRoot: string,
  target: string,
  modified: string,
  now: Date = new Date(),
): Promise<ApplyResult> {
  const absTarget = isAbsolute(target) ? target : resolve(repoRoot, target);
  // Sanity: target must be inside repoRoot.
  const relTarget = relative(repoRoot, absTarget);
  if (relTarget.startsWith("..") || isAbsolute(relTarget)) {
    throw new Error(`applyWithBackup: target '${target}' is outside repo root`);
  }
  const backupDir = safeJoin(
    repoRoot,
    ".security-mcp",
    "backups",
    isoTimestamp(now),
    dirname(relTarget) === "." ? "" : dirname(relTarget),
  );
  await mkdir(backupDir, { recursive: true });
  const backupName = (relTarget.split(/[\\/]/).pop() ?? "file") + ".bak";
  const backupPath = join(backupDir, backupName);

  // Read current contents (may be empty for new files).
  let original = "";
  let sha256Before = sha256Hex("");
  try {
    original = await readFile(absTarget, "utf8");
    sha256Before = sha256Hex(original);
    await writeFile(backupPath, original, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
  }

  await mkdir(dirname(absTarget), { recursive: true });
  const tmp = `${absTarget}.tmp-${process.pid}-${Date.now()}`;
  await writeFile(tmp, modified, { encoding: "utf8", flag: "wx" });
  await rename(tmp, absTarget);

  return { backupPath, sha256Before, writtenPath: absTarget };
}

export interface RollbackResult {
  rolledBack: boolean;
  reason: string;
}

/**
 * Restore a file from a backup. Idempotent: refuses to roll back if the
 * current file's hash no longer matches `sha256Before`.
 */
export async function rollback(
  repoRoot: string,
  target: string,
  backupPath: string,
  sha256Before: string,
): Promise<RollbackResult> {
  const absTarget = isAbsolute(target) ? target : resolve(repoRoot, target);
  let current = "";
  try {
    current = await readFile(absTarget, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
  }
  if (sha256Hex(current) !== sha256Before) {
    return {
      rolledBack: false,
      reason: "current file hash no longer matches pre-apply hash; manual review required",
    };
  }
  let backup = "";
  try {
    backup = await readFile(backupPath, "utf8");
  } catch (err) {
    return {
      rolledBack: false,
      reason: `backup not readable: ${(err as Error).message}`,
    };
  }
  const tmp = `${absTarget}.tmp-${process.pid}-${Date.now()}`;
  await writeFile(tmp, backup, { encoding: "utf8", flag: "wx" });
  await rename(tmp, absTarget);
  return { rolledBack: true, reason: "restored from backup" };
}

function isoTimestamp(d: Date): string {
  // 2026-07-06T19-42-11-034Z (no colons — safe for Windows + paths)
  return d.toISOString().replace(/[:.]/g, "-");
}

/** Convert an absolute path to a backup key (the relative subdir + name). */
export function backupKey(repoRoot: string, absTarget: string): string {
  const rel = relative(repoRoot, absTarget);
  return rel.split(/[\\/]/).join(sep);
}
