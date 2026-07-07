import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, join, resolve, sep } from "node:path";
import { createHash } from "node:crypto";

/** Read a UTF-8 text file; returns "" on ENOENT. */
export async function readTextFile(path: string): Promise<string> {
  try {
    return await readFile(path, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return "";
    throw err;
  }
}

/** Read a file as Buffer. */
export async function readBinaryFile(path: string): Promise<Buffer> {
  return readFile(path);
}

/** Write a file atomically: write to a temp sibling, then rename. */
export async function writeTextFileAtomic(path: string, contents: string): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const tmp = `${path}.tmp-${process.pid}-${Date.now()}`;
  await writeFile(tmp, contents, { encoding: "utf8", flag: "wx" });
  await rename(tmp, path);
}

/** Write a binary file atomically. */
export async function writeBinaryFileAtomic(path: string, contents: Buffer): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const tmp = `${path}.tmp-${process.pid}-${Date.now()}`;
  await writeFile(tmp, contents, { flag: "wx" });
  await rename(tmp, path);
}

/** Ensure a directory exists. */
export async function ensureDir(path: string): Promise<void> {
  await mkdir(path, { recursive: true });
}

/** Convert any path to absolute. */
export function toAbsolute(path: string, baseDir: string = process.cwd()): string {
  return isAbsolute(path) ? path : resolve(baseDir, path);
}

/** Stable SHA-256 hex digest. */
export function sha256Hex(input: string | Buffer): string {
  return createHash("sha256").update(input).digest("hex");
}

/** Path separator for the current platform. */
export const PATH_SEP = sep;

/** Race a promise against a timeout; rejects with a labelled error on expiry. */
export async function withTimeout<T>(
  promise: Promise<T>,
  ms: number,
  label: string,
): Promise<T> {
  if (!Number.isFinite(ms) || ms <= 0) {
    throw new Error(`withTimeout: invalid timeout (${ms}) for ${label}`);
  }
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => reject(new Error(`timeout after ${ms}ms: ${label}`)), ms);
  });
  try {
    return await Promise.race([promise, timeout]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

/** Format a Date as a Windows-safe ISO timestamp (no colons). */
export function isoTimestampSafe(d: Date = new Date()): string {
  return d.toISOString().replace(/[:.]/g, "-");
}

/** Recursively list files under `root` that match the predicate. Bounded depth. */
export async function* walkFiles(
  root: string,
  predicate: (abs: string) => boolean,
  options: { maxDepth?: number; skip?: RegExp[] } = {},
): AsyncGenerator<string> {
  const maxDepth = options.maxDepth ?? 6;
  const skip = options.skip ?? [/node_modules/, /\.git/, /dist/, /build/, /target/];
  async function* recurse(dir: string, depth: number): AsyncGenerator<string> {
    if (depth > maxDepth) return;
    let entries: import("node:fs").Dirent[];
    try {
      entries = await (await import("node:fs/promises")).readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (skip.some((re) => re.test(e.name))) continue;
      const full = join(dir, e.name);
      if (e.isDirectory()) yield* recurse(full, depth + 1);
      else if (e.isFile() && predicate(full)) yield full;
    }
  }
  yield* recurse(root, 0);
}
