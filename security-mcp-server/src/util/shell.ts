import { execa } from "execa";

/** Resolve a binary on PATH. Returns absolute path or null. Cross-platform. */
export async function which(bin: string): Promise<string | null> {
  if (!bin || bin.includes("/") || bin.includes("\\")) {
    // Caller supplied a path; trust it but verify it exists.
    try {
      await execa(bin, ["--version"], { reject: false, timeout: 5_000 });
      return bin;
    } catch {
      return null;
    }
  }
  const cmd = process.platform === "win32" ? "where" : "which";
  try {
    const res = await execa(cmd, [bin], { reject: false, timeout: 5_000 });
    if (res.exitCode === 0 && typeof res.stdout === "string") {
      const first = res.stdout.split(/\r?\n/).find((line) => line.trim().length > 0);
      return first?.trim() ?? null;
    }
  } catch {
    // fallthrough
  }
  return null;
}
