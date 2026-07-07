import { readFile, readdir, stat } from "node:fs/promises";
import { join } from "node:path";
import type { DetectionMatch, StackPlugin, ExtraRule } from "./plugin.interface.js";

const SPRING_BOOT_RULES: ExtraRule[] = [
  {
    id: "spring-mvc-sql-injection",
    language: "java",
    severity: "error",
    yaml: `rules:
  - id: spring-mvc-sql-injection
    pattern-regex: '@(Get|Post|Put|Delete|Request)Mapping.*\\n[\\s\\S]*?(createQuery|createNativeQuery)\\(".*"\\s*\\+'
    message: "Possible SQL injection in Spring controller"
    languages: [java]
    severity: ERROR
`,
  },
];

export const javaSpringPlugin: StackPlugin = {
  id: "java-spring-boot",
  displayName: "Java + Spring Boot",
  async detect(rootPath) {
    const evidence: string[] = [];
    let confidence = 0;
    const pomPath = await findFile(rootPath, "pom.xml");
    if (pomPath) {
      const text = (await readIfText(pomPath)) ?? "";
      evidence.push(`pom.xml (${pomPath})`);
      if (/<artifactId>spring-boot-starter/.test(text)) {
        confidence += 0.5;
        evidence.push("spring-boot-starter / spring-boot-maven-plugin");
      }
      if (/<groupId>org\.springframework\.boot<\/groupId>/.test(text)) {
        confidence += 0.2;
        evidence.push("org.springframework.boot groupId");
      }
    }
    const gradlePath =
      (await findFile(rootPath, "build.gradle")) ?? (await findFile(rootPath, "build.gradle.kts"));
    if (gradlePath) {
      const text = (await readIfText(gradlePath)) ?? "";
      evidence.push(gradlePath);
      if (/org\.springframework\.boot/.test(text)) {
        confidence += 0.5;
        evidence.push("org.springframework.boot in Gradle");
      }
    }
    const mainApp = await findFile(rootPath, "Application.java", 6);
    if (mainApp && /@SpringBootApplication/.test((await readIfText(mainApp)) ?? "")) {
      confidence += 0.3;
      evidence.push("@SpringBootApplication");
    }
    if (confidence === 0) return [];
    return [
      { id: this.id, displayName: this.displayName, confidence: Math.min(confidence, 0.99), evidence },
    ];
  },
  getExtraRules() {
    return SPRING_BOOT_RULES;
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
        if (["node_modules", ".git", "target", "build", "dist"].includes(e.name)) continue;
        queue.push({ dir: full, depth: depth + 1 });
      } else if (e.name === name) return full;
    }
  }
  return null;
}
