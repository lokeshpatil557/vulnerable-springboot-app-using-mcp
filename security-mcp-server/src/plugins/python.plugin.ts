import { readFile, readdir, stat } from "node:fs/promises";
import { join } from "node:path";
import type { DetectionMatch, StackPlugin, ExtraRule } from "./plugin.interface.js";

const PYTHON_RULES: ExtraRule[] = [
  {
    id: "python-django-rawsql",
    language: "python",
    severity: "error",
    yaml: `rules:
  - id: python-django-rawsql
    pattern: |
      $CURSOR.execute(f"... {$X} ...")
    message: "Formatted SQL string with f-string — use parameterized queries"
    languages: [python]
    severity: ERROR
`,
  },
];

export const pythonPlugin: StackPlugin = {
  id: "python",
  displayName: "Python (Django / Flask / FastAPI)",
  async detect(rootPath) {
    const evidence: string[] = [];
    const matches: DetectionMatch[] = [];
    if (await pathExists(join(rootPath, "manage.py"))) {
      matches.push({
        id: "python-django",
        displayName: "Python + Django",
        confidence: 0.85,
        evidence: ["manage.py"],
      });
    }
    const reqs = (await readIfText(join(rootPath, "requirements.txt"))) ?? "";
    if (/\bfastapi\b/i.test(reqs)) {
      matches.push({
        id: "python-fastapi",
        displayName: "Python + FastAPI",
        confidence: 0.85,
        evidence: ["fastapi in requirements.txt"],
      });
    }
    if (/\bflask\b/i.test(reqs)) {
      matches.push({
        id: "python-flask",
        displayName: "Python + Flask",
        confidence: 0.75,
        evidence: ["flask in requirements.txt"],
      });
    }
    if (matches.length === 0) return [];
    evidence.push(`requirements.txt: ${reqs.slice(0, 100)}`);
    return matches;
  },
  getExtraRules() {
    return PYTHON_RULES;
  },
};

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
