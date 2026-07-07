import { readFile, readdir, stat } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";
import type { DetectionMatch, StackAdapter } from "./base.js";

async function pathExists(p: string): Promise<boolean> {
  try {
    await stat(p);
    return true;
  } catch {
    return false;
  }
}

async function readIfText(p: string): Promise<string | null> {
  try {
    return await readFile(p, "utf8");
  } catch {
    return null;
  }
}

async function findFile(root: string, name: string, maxDepth = 4): Promise<string | null> {
  // Bounded BFS — production code would use a real walker; this is enough
  // for the common single-app repo shapes.
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
        if (e.name === "node_modules" || e.name === ".git" || e.name === "target" || e.name === "build" || e.name === "dist") continue;
        queue.push({ dir: full, depth: depth + 1 });
      } else if (e.name === name) {
        return full;
      }
    }
  }
  return null;
}

/** Java + Spring Boot — pom.xml or build.gradle + @SpringBootApplication. */
export const javaSpringBoot: StackAdapter = {
  id: "java-spring-boot",
  displayName: "Java + Spring Boot",
  async match(root) {
    const evidence: string[] = [];
    let confidence = 0;

    const pomPath = await findFile(root, "pom.xml");
    if (pomPath) {
      const text = (await readIfText(pomPath)) ?? "";
      evidence.push(`pom.xml (${pomPath})`);
      if (/<artifactId>spring-boot-starter/.test(text) || /spring-boot-maven-plugin/.test(text)) {
        confidence += 0.5;
        evidence.push("spring-boot-starter / spring-boot-maven-plugin");
      }
      if (/<groupId>org\.springframework\.boot<\/groupId>/.test(text)) {
        confidence += 0.2;
        evidence.push("org.springframework.boot groupId");
      }
    }
    const gradlePath = await findFile(root, "build.gradle");
    const gradleKts = await findFile(root, "build.gradle.kts");
    const gradle = gradlePath ?? gradleKts;
    if (gradle) {
      const text = (await readIfText(gradle)) ?? "";
      evidence.push(`${gradlePath ? "build.gradle" : "build.gradle.kts"}`);
      if (/org\.springframework\.boot/.test(text)) {
        confidence += 0.5;
        evidence.push("org.springframework.boot in Gradle");
      }
    }

    // Look for @SpringBootApplication under src/main/java.
    const mainApp = await findFile(root, "Application.java", 6);
    if (mainApp) {
      const text = (await readIfText(mainApp)) ?? "";
      if (/@SpringBootApplication/.test(text)) {
        confidence += 0.3;
        evidence.push("@SpringBootApplication");
      }
    }

    if (confidence === 0) return [];
    return [
      {
        adapterId: "java-spring-boot",
        displayName: "Java + Spring Boot",
        confidence: Math.min(confidence, 0.99),
        evidence,
      },
    ];
  },
};

/** .NET / ASP.NET — *.csproj + Program.cs / Startup.cs. */
export const dotnetAspnet: StackAdapter = {
  id: "dotnet-aspnet",
  displayName: ".NET / ASP.NET",
  async match(root) {
    const evidence: string[] = [];
    let confidence = 0;
    const csproj = await findFile(root, "*.csproj");
    if (csproj) {
      const text = (await readIfText(csproj)) ?? "";
      evidence.push(csproj);
      if (/<TargetFramework>net\d/.test(text)) confidence += 0.3;
      if (/Microsoft\.AspNetCore/.test(text) || /UseStartup/.test(text)) {
        confidence += 0.5;
        evidence.push("Microsoft.AspNetCore");
      }
    }
    const programCs = await findFile(root, "Program.cs");
    const startupCs = await findFile(root, "Startup.cs");
    if (programCs || startupCs) {
      confidence += 0.2;
      evidence.push(programCs ?? startupCs!);
    }
    if (confidence === 0) return [];
    return [
      {
        adapterId: "dotnet-aspnet",
        displayName: ".NET / ASP.NET",
        confidence: Math.min(confidence, 0.99),
        evidence,
      },
    ];
  },
};

/** Express.js — package.json with express + an app.get/post style. */
export const express: StackAdapter = {
  id: "express",
  displayName: "Express.js",
  async match(root) {
    const evidence: string[] = [];
    let confidence = 0;
    const pkgPath = await findFile(root, "package.json");
    if (!pkgPath) return [];
    const pkg = JSON.parse((await readIfText(pkgPath)) ?? "{}") as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
    };
    const deps = { ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) };
    if (deps["express"] && !deps["@nestjs/core"]) {
      confidence += 0.7;
      evidence.push("express in package.json");
    }
    if (confidence === 0) return [];
    return [
      {
        adapterId: "express",
        displayName: "Express.js",
        confidence: Math.min(confidence, 0.99),
        evidence,
      },
    ];
  },
};

/** NestJS — package.json with @nestjs/core. */
export const nestjs: StackAdapter = {
  id: "nestjs",
  displayName: "NestJS",
  async match(root) {
    const pkgPath = await findFile(root, "package.json");
    if (!pkgPath) return [];
    const pkg = JSON.parse((await readIfText(pkgPath)) ?? "{}") as {
      dependencies?: Record<string, string>;
    };
    const deps = pkg.dependencies ?? {};
    if (deps["@nestjs/core"] && deps["@nestjs/common"]) {
      return [
        {
          adapterId: "nestjs",
          displayName: "NestJS",
          confidence: 0.9,
          evidence: ["@nestjs/core + @nestjs/common in package.json"],
        },
      ];
    }
    return [];
  },
};

/** Django — manage.py + settings.py. */
export const pythonDjango: StackAdapter = {
  id: "python-django",
  displayName: "Python + Django",
  async match(root) {
    if (!(await pathExists(join(root, "manage.py")))) return [];
    const settings = await findFile(root, "settings.py");
    if (!settings) return [];
    return [
      {
        adapterId: "python-django",
        displayName: "Python + Django",
        confidence: 0.9,
        evidence: ["manage.py", settings],
      },
    ];
  },
};

/** Flask — flask in requirements. */
export const pythonFlask: StackAdapter = {
  id: "python-flask",
  displayName: "Python + Flask",
  async match(root) {
    const reqs = (await readIfText(join(root, "requirements.txt"))) ?? "";
    if (/\bflask\b/i.test(reqs)) {
      return [
        {
          adapterId: "python-flask",
          displayName: "Python + Flask",
          confidence: 0.8,
          evidence: ["flask in requirements.txt"],
        },
      ];
    }
    return [];
  },
};

/** FastAPI — fastapi in requirements. */
export const pythonFastapi: StackAdapter = {
  id: "python-fastapi",
  displayName: "Python + FastAPI",
  async match(root) {
    const reqs = (await readIfText(join(root, "requirements.txt"))) ?? "";
    if (/\bfastapi\b/i.test(reqs)) {
      return [
        {
          adapterId: "python-fastapi",
          displayName: "Python + FastAPI",
          confidence: 0.85,
          evidence: ["fastapi in requirements.txt"],
        },
      ];
    }
    return [];
  },
};

/** React — react/react-dom in package.json. */
export const react: StackAdapter = {
  id: "react",
  displayName: "React",
  async match(root) {
    const pkgPath = await findFile(root, "package.json");
    if (!pkgPath) return [];
    const pkg = JSON.parse((await readIfText(pkgPath)) ?? "{}") as {
      dependencies?: Record<string, string>;
    };
    const deps = pkg.dependencies ?? {};
    if (deps["react"] && !deps["next"]) {
      return [
        {
          adapterId: "react",
          displayName: "React",
          confidence: 0.85,
          evidence: ["react in package.json (no next)"],
        },
      ];
    }
    return [];
  },
};

/** Angular — angular.json + @angular/core. */
export const angular: StackAdapter = {
  id: "angular",
  displayName: "Angular",
  async match(root) {
    if (!existsSync(join(root, "angular.json"))) return [];
    const pkgPath = await findFile(root, "package.json");
    const pkg = pkgPath ? (JSON.parse((await readIfText(pkgPath)) ?? "{}") as { dependencies?: Record<string, string> }) : null;
    if (pkg?.dependencies?.["@angular/core"]) {
      return [
        {
          adapterId: "angular",
          displayName: "Angular",
          confidence: 0.95,
          evidence: ["angular.json", "@angular/core in package.json"],
        },
      ];
    }
    return [];
  },
};

/** Vue.js — vue in package.json + at least one .vue file. */
export const vue: StackAdapter = {
  id: "vue",
  displayName: "Vue.js",
  async match(root) {
    const pkgPath = await findFile(root, "package.json");
    if (!pkgPath) return [];
    const pkg = JSON.parse((await readIfText(pkgPath)) ?? "{}") as {
      dependencies?: Record<string, string>;
    };
    if (pkg.dependencies?.["vue"] && !pkg.dependencies?.["nuxt"]) {
      return [
        {
          adapterId: "vue",
          displayName: "Vue.js",
          confidence: 0.85,
          evidence: ["vue in package.json"],
        },
      ];
    }
    return [];
  },
};

/** Microservices — multiple service manifests, k8s, or compose with >2 services. */
export const microservices: StackAdapter = {
  id: "microservices",
  displayName: "Microservices",
  async match(root) {
    const evidence: string[] = [];
    let confidence = 0;
    // Multiple Dockerfiles in subdirectories.
    let dockerfileCount = 0;
    const stack: { dir: string; depth: number }[] = [{ dir: root, depth: 0 }];
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
          if (e.name === "node_modules" || e.name === ".git" || e.name === "target" || e.name === "build") continue;
          stack.push({ dir: full, depth: depth + 1 });
        } else if (e.name === "Dockerfile" || e.name === "Dockerfile.prod") {
          dockerfileCount++;
        }
      }
    }
    if (dockerfileCount >= 3) {
      confidence += 0.4;
      evidence.push(`${dockerfileCount} Dockerfiles`);
    } else if (dockerfileCount >= 2) {
      confidence += 0.2;
      evidence.push(`${dockerfileCount} Dockerfiles`);
    }

    // docker-compose with >2 services.
    const composeCandidates = ["docker-compose.yml", "docker-compose.yaml", "compose.yaml"];
    for (const name of composeCandidates) {
      const text = (await readIfText(join(root, name))) ?? "";
      if (text) {
        const services = (text.match(/^\s{2}\w[\w-]*:\s*$/gm) ?? []).length;
        if (services >= 3) {
          confidence += 0.4;
          evidence.push(`${name} with ${services} services`);
        } else if (services >= 2) {
          confidence += 0.2;
          evidence.push(`${name} with ${services} services`);
        }
      }
    }

    // Multiple independently buildable service roots (pom.xml or package.json
    // in subdirs at the same level).
    let serviceRoots = 0;
    try {
      const entries = await readdir(root, { withFileTypes: true });
      for (const e of entries) {
        if (!e.isDirectory()) continue;
        const sub = join(root, e.name);
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
    if (serviceRoots >= 3) {
      confidence += 0.4;
      evidence.push(`${serviceRoots} independently buildable service roots`);
    } else if (serviceRoots >= 2) {
      confidence += 0.2;
      evidence.push(`${serviceRoots} independently buildable service roots`);
    }

    if (confidence === 0) return [];
    return [
      {
        adapterId: "microservices",
        displayName: "Microservices",
        confidence: Math.min(confidence, 0.99),
        evidence,
      },
    ];
  },
};

/** Containerized — Dockerfile, docker-compose*, k8s manifests. */
export const containerized: StackAdapter = {
  id: "containerized",
  displayName: "Containerized",
  async match(root) {
    const evidence: string[] = [];
    let confidence = 0;
    if (existsSync(join(root, "Dockerfile"))) {
      confidence += 0.5;
      evidence.push("Dockerfile");
    }
    for (const name of ["docker-compose.yml", "docker-compose.yaml", "compose.yaml"]) {
      if (existsSync(join(root, name))) {
        confidence += 0.3;
        evidence.push(name);
        break;
      }
    }
    if (existsSync(join(root, "k8s")) || existsSync(join(root, "kubernetes"))) {
      confidence += 0.3;
      evidence.push("k8s/ or kubernetes/ directory");
    }
    if (confidence === 0) return [];
    return [
      {
        adapterId: "containerized",
        displayName: "Containerized",
        confidence: Math.min(confidence, 0.95),
        evidence,
      },
    ];
  },
};

/** Monolith fallback — always matches with very low confidence. */
export const monolith: StackAdapter = {
  id: "monolith",
  displayName: "Monolith (fallback)",
  match() {
    return [
      {
        adapterId: "monolith",
        displayName: "Monolith (fallback)",
        confidence: 0.2,
        evidence: ["no specific architecture signal detected"],
      },
    ];
  },
};
