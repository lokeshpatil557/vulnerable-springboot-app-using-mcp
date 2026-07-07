import { describe, it, expect } from "vitest";
import { getAdapters } from "../src/adapters/registry.js";

describe("adapters/registry", () => {
  it("returns a non-empty list with a fallback monolith adapter last", () => {
    const a = getAdapters();
    expect(a.length).toBeGreaterThan(0);
    const last = a[a.length - 1]!;
    expect(last.id).toBe("monolith");
  });

  it("contains the 12 advertised stacks", () => {
    const ids = new Set(getAdapters().map((a) => a.id));
    for (const id of [
      "java-spring-boot",
      "dotnet-aspnet",
      "express",
      "nestjs",
      "python-django",
      "python-flask",
      "python-fastapi",
      "react",
      "angular",
      "vue",
      "microservices",
      "containerized",
      "monolith",
    ]) {
      expect(ids.has(id)).toBe(true);
    }
  });
});
