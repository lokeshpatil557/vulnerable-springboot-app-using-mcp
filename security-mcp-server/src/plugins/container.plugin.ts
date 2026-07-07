import { existsSync, readdir, stat } from "node:fs";
import { join } from "node:path";
import type { DetectionMatch, StackPlugin, ExtraRule } from "./plugin.interface.js";

const CONTAINER_RULES: ExtraRule[] = [
  {
    id: "dockerfile-root-user",
    language: "dockerfile",
    severity: "warning",
    yaml: `rules:
  - id: dockerfile-root-user
    pattern: |
      FROM ...
      ...
      USER root
    message: "Container runs as root — prefer a non-root USER"
    languages: [dockerfile]
    severity: WARNING
`,
  },
];

export const containerPlugin: StackPlugin = {
  id: "containerized",
  displayName: "Containerized / Microservices",
  async detect(rootPath) {
    const evidence: string[] = [];
    let confidence = 0;
    if (existsSync(join(rootPath, "Dockerfile"))) {
      confidence += 0.5;
      evidence.push("Dockerfile");
    }
    for (const name of ["docker-compose.yml", "docker-compose.yaml", "compose.yaml"]) {
      if (existsSync(join(rootPath, name))) {
        confidence += 0.3;
        evidence.push(name);
        break;
      }
    }
    if (existsSync(join(rootPath, "k8s")) || existsSync(join(rootPath, "kubernetes"))) {
      confidence += 0.3;
      evidence.push("k8s/ or kubernetes/");
    }
    let dockerfileCount = 0;
    let serviceRoots = 0;
    const stack: { dir: string; depth: number }[] = [{ dir: rootPath, depth: 0 }];
    while (stack.length) {
      const { dir, depth } = stack.pop()!;
      if (depth > 4) continue;
      let entries: import("node:fs").Dirent[] = [];
      try {
        entries = await readdir(dir, { withFileTypes: true });
      } catch {
        continue;
      }
      for (const e of entries) {
        const full = join(dir, e.name);
        if (e.isDirectory()) {
          if (["node_modules", ".git", "dist", "build", "target"].includes(e.name)) continue;
          stack.push({ dir: full, depth: depth + 1 });
        } else if (e.name === "Dockerfile" || e.name === "Dockerfile.prod") {
          dockerfileCount++;
        }
      }
    }
    try {
      const entries = await readdir(rootPath, { withFileTypes: true });
      for (const e of entries) {
        if (!e.isDirectory()) continue;
        const sub = join(rootPath, e.name);
        if (
          existsSync(join(sub, "pom.xml")) ||
          existsSync(join(sub, "package.json")) ||
          existsSync(join(sub, "go.mod"))
        ) {
          serviceRoots++;
        }
      }
    } catch {
      // ignore
    }
    if (dockerfileCount >= 3 || serviceRoots >= 3) {
      confidence += 0.4;
      evidence.push(`${Math.max(dockerfileCount, serviceRoots)} services detected`);
    } else if (dockerfileCount >= 2 || serviceRoots >= 2) {
      confidence += 0.2;
      evidence.push(`${Math.max(dockerfileCount, serviceRoots)} services detected`);
    }
    if (confidence === 0) return [];
    return [
      {
        id: dockerfileCount >= 2 || serviceRoots >= 2 ? "microservices" : "containerized",
        displayName: dockerfileCount >= 2 || serviceRoots >= 2 ? "Microservices" : "Containerized",
        confidence: Math.min(confidence, 0.99),
        evidence,
      },
    ];
  },
  getExtraRules() {
    return CONTAINER_RULES;
  },
};
