import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

/** Read a text file as UTF-8. */
export async function readTextFile(path: string): Promise<string> {
  return readFile(path, "utf8");
}

/** Write a text file atomically: write to a temp sibling, then rename. */
export async function writeTextFileAtomic(path: string, contents: string): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const tmp = `${path}.tmp-${process.pid}-${Date.now()}`;
  await writeFile(tmp, contents, { encoding: "utf8", flag: "wx" });
  // rename within the same directory is atomic on both NTFS and POSIX.
  await rename(tmp, path);
}
