import { describe, it, expect } from "vitest";
import { sha256Hex, shortHash } from "../src/util/hash.js";
import { monotonicMs, withTimeout } from "../src/util/time.js";

describe("util/hash", () => {
  it("sha256Hex is deterministic and 64 hex chars", () => {
    expect(sha256Hex("abc")).toMatch(/^[a-f0-9]{64}$/);
    expect(sha256Hex("abc")).toBe(sha256Hex("abc"));
  });

  it("shortHash returns the first N chars", () => {
    expect(shortHash("abc", 8)).toHaveLength(8);
    expect(shortHash("abc", 16)).toHaveLength(16);
  });
});

describe("util/time", () => {
  it("monotonicMs is non-decreasing", () => {
    const a = monotonicMs();
    const b = monotonicMs();
    expect(b).toBeGreaterThanOrEqual(a);
  });

  it("withTimeout resolves before the deadline", async () => {
    const v = await withTimeout(Promise.resolve(42), 1000, "test");
    expect(v).toBe(42);
  });

  it("withTimeout rejects after the deadline", async () => {
    await expect(
      withTimeout(new Promise(() => {}), 10, "slow"),
    ).rejects.toThrow(/timeout/);
  });
});
