import { readFile, readdir, stat } from "node:fs/promises";
import { join } from "node:path";
import type { DetectionMatch, StackPlugin, ExtraRule } from "./plugin.interface.js";

const DOTNET_RULES: ExtraRule[] = [
  {
    id: "aspnet-sqlcommand-concat",
    language: "csharp",
    severity: "error",
    yaml: `rules:
  - id: aspnet-sqlcommand-concat
    pattern: new SqlCommand("..." + $X)
    message: "Possible SQL injection in SqlCommand"
    languages: [csharp]
    severity: ERROR
`,
  },
];

export const dotnetPlugin: StackPlugin = {
  id: "dotnet-aspnet",
  displayName: ".NET / ASP.NET",
  async detect(rootPath) {
    const evidence: string[] = [];
    let confidence = 0;
    const csproj = await findFile(rootPath, "*.csproj");
    if (csproj) {
      const text = (await readIfText(csproj)) ?? "";
      evidence.push(csproj);
      if (/<TargetFramework>net\d/.test(text)) confidence += 0.3;
      if (/Microsoft\.AspNetCore/.test(text) || /UseStartup/.test(text)) {
        confidence += 0.5;
        evidence.push("Microsoft.AspNetCore");
      }
    }
    const programCs = await findFile(rootPath, "Program.cs");
    const startupCs = await findFile(rootPath, "Startup.cs");
    if (programCs || startupCs) {
      confidence += 0.2;
      evidence.push(programCs ?? startupCs!);
    }
    if (confidence === 0) return [];
    return [
      { id: this.id, displayName: this.displayName, confidence: Math.min(confidence, 0.99), evidence },
    ];
  },
  getExtraRules() {
    return DOTNET_RULES;
  },
};

async function readIfText(p: string): Promise<string | null> {
  try {
    return await readFile(p, "utf8");
  } catch {
    return null;
  }
}

async function findFile(root: string, name: string, maxDepth = 4): Promise<string | null> {
  const pattern = name.replace(/\*/g, ".*");
  const re = new RegExp(`^${pattern}$`);
  const queue: { dir: string; depth: number }[] = [{ dir: root, depth: 0 }];
  while (queue.length) {
    const { dir, depth } = queue.shift()!;
    if (depth > maxDepth) continue;
    let entries: import("node:fs").Dirent[] = [];
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      const full = join(dir, e.name);
      if (e.isDirectory()) {
        if (["node_modules", ".git", "bin", "obj"].includes(e.name)) continue;
        queue.push({ dir: full, depth: depth + 1 });
      } else if (re.test(e.name)) return full;
    }
  }
  return null;
}
