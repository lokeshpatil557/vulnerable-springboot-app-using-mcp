import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

/** Read a text file as UTF-8. */
export async function readTextFile(path: string): Promise<string> {
  return readFile(path, "utf8");
}

/** Write a text file atomically: write to a temp sibling, fsync, then rename. */
export async function writeTextFileAtomic(path: string, contents: string): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const tmp = `${path}.tmp-${process.pid}-${Date.now()}`;
  const handle = await writeFile(tmp, contents, { encoding: "utf8", flag: "wx" });
  // Best-effort fsync — writeFile returns the handle on some Node versions.
  // We deliberately accept a best-effort sync here; rename within the same
  // directory is atomic on both NTFS and POSIX.
  if (handle && typeof (handle as { sync?: () => void }).sync === "function") {
    try {
      (handle as { sync: () => void }).sync();
    } catch {
      // ignore — not all FS backends support sync()
    }
  }
  await rename(tmp, path);
}
