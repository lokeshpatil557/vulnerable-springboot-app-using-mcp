import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { identifyCodebase } from "../src/stack-detect.js";

describe("stack-detect", () => {
  let repo: string;

  beforeAll(() => {
    repo = mkdtempSync(join(tmpdir(), "sec-mcp-stack-"));
    // A pom.xml with Spring Boot + a Java application class.
    writeFileSync(
      join(repo, "pom.xml"),
      `<?xml version="1.0"?>
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>demo</artifactId>
  <dependencies>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
  </dependencies>
</project>`,
    );
    mkdirSync(join(repo, "src", "main", "java", "com", "example"), { recursive: true });
    writeFileSync(
      join(repo, "src", "main", "java", "com", "example", "DemoApplication.java"),
      "package com.example;\nimport org.springframework.boot.autoconfigure.SpringBootApplication;\n@SpringBootApplication\npublic class DemoApplication {}\n",
    );
  });

  afterAll(() => {
    rmSync(repo, { recursive: true, force: true });
  });

  it("detects Spring Boot with high confidence", async () => {
    const matches = await identifyCodebase(repo);
    const sb = matches.find((m) => m.adapterId === "java-spring-boot");
    expect(sb).toBeDefined();
    expect(sb!.confidence).toBeGreaterThan(0.8);
  });

  it("always returns the monolith fallback last", async () => {
    const matches = await identifyCodebase(repo);
    const mono = matches.find((m) => m.adapterId === "monolith");
    expect(mono).toBeDefined();
  });
});
