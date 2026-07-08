import { existsSync } from "node:fs";
import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import type { DetectionMatch, StackPlugin, ExtraRule } from "./plugin.interface.js";

const FRONTEND_RULES: ExtraRule[] = [
  {
    id: "react-dangerously-set-inner-html",
    language: "javascript",
    severity: "warning",
    yaml: `rules:
  - id: react-dangerously-set-inner-html
    pattern: dangerouslySetInnerHTML={{__html: $X}}
    message: "Untrusted HTML rendered — review the source of $X"
    languages: [javascript, typescript]
    severity: WARNING
`,
  },
];

interface PackageJson {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}

export const frontendPlugin: StackPlugin = {
  id: "frontend",
  displayName: "Frontend (React / Angular / Vue)",
  async detect(rootPath) {
    const matches: DetectionMatch[] = [];
    const pkgPath = await findFile(rootPath, "package.json");
    if (pkgPath) {
      const text = (await readIfText(pkgPath)) ?? "{}";
      let pkg: PackageJson;
      try {
        pkg = JSON.parse(text) as PackageJson;
      } catch {
        pkg = {};
      }
      const deps = { ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) };
      if (deps["react"] && !deps["next"]) {
        matches.push({
          id: "react",
          displayName: "React",
          confidence: 0.85,
          evidence: ["react in package.json"],
        });
      }
      if (deps["vue"] && !deps["nuxt"]) {
        matches.push({
          id: "vue",
          displayName: "Vue.js",
          confidence: 0.85,
          evidence: ["vue in package.json"],
        });
      }
      if (deps["@angular/core"]) {
        matches.push({
          id: "angular",
          displayName: "Angular",
          confidence: 0.95,
          evidence: ["@angular/core"],
        });
      }
    }
    if (existsSync(join(rootPath, "angular.json")) && !matches.find((m) => m.id === "angular")) {
      matches.push({ id: "angular", displayName: "Angular", confidence: 0.6, evidence: ["angular.json"] });
    }
    return matches;
  },
  getExtraRules() {
    return FRONTEND_RULES;
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
        if (["node_modules", ".git", "dist", "build"].includes(e.name)) continue;
        queue.push({ dir: full, depth: depth + 1 });
      } else if (e.name === name) return full;
    }
  }
  return null;
}
