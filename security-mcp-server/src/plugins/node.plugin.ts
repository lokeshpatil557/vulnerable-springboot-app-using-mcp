import { readFile, readdir, stat } from "node:fs/promises";
import { join } from "node:path";
import type { DetectionMatch, StackPlugin, ExtraRule } from "./plugin.interface.js";

const NODE_RULES: ExtraRule[] = [
  {
    id: "node-express-open-redirect",
    language: "javascript",
    severity: "warning",
    yaml: `rules:
  - id: node-express-open-redirect
    patterns:
      - pattern: res.redirect(req.query.$X)
    message: "Open redirect via unvalidated query parameter"
    languages: [javascript, typescript]
    severity: WARNING
`,
  },
];

interface PackageJson {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}

export const nodePlugin: StackPlugin = {
  id: "node-js",
  displayName: "Node.js (Express / NestJS)",
  async detect(rootPath) {
    const pkgPath = await findFile(rootPath, "package.json");
    if (!pkgPath) return [];
    const text = (await readIfText(pkgPath)) ?? "{}";
    let pkg: PackageJson;
    try {
      pkg = JSON.parse(text) as PackageJson;
    } catch {
      pkg = {};
    }
    const deps = { ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) };
    const matches: DetectionMatch[] = [];
    const evidence: string[] = [`package.json (${pkgPath})`];
    if (deps["@nestjs/core"] && deps["@nestjs/common"]) {
      matches.push({
        id: "nestjs",
        displayName: "NestJS",
        confidence: 0.9,
        evidence: ["@nestjs/core + @nestjs/common", ...evidence],
      });
    } else if (deps["express"]) {
      matches.push({
        id: "express",
        displayName: "Express.js",
        confidence: 0.7,
        evidence: ["express in package.json", ...evidence],
      });
    } else if (Object.keys(deps).length > 0) {
      matches.push({
        id: "node-js",
        displayName: "Node.js",
        confidence: 0.4,
        evidence: ["package.json present"],
      });
    }
    return matches;
  },
  getExtraRules() {
    return NODE_RULES;
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
