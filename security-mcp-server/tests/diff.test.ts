import { describe, it, expect } from "vitest";
import { generateUnifiedDiff } from "../src/diff.js";

describe("diff.generateUnifiedDiff", () => {
  it("produces a unified diff for a one-line change", () => {
    const before = "const x = 1;\nconst y = 2;\n";
    const after = "const x = 1;\nconst y = 3;\n";
    const d = generateUnifiedDiff("a.js", before, after);
    expect(d).toMatch(/^Index: a\.js/);
    expect(d).toMatch(/--- a\.js/);
    expect(d).toMatch(/\+\+\+ b\.js/);
    expect(d).toMatch(/-const y = 2;/);
    expect(d).toMatch(/\+const y = 3;/);
  });

  it("returns an empty diff for identical contents", () => {
    const d = generateUnifiedDiff("a.js", "same", "same");
    // The header is always present; just confirm no hunk markers.
    expect(d).not.toMatch(/^@@/m);
  });
});
