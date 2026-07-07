/**
 * Stack detection contract. Each adapter matches the repository against
 * the markers for a specific framework/language and returns a confidence
 * score (0..1) and a list of evidence (matched files / strings).
 *
 * Adapters are statically registered in `./registry.ts`; there is no
 * dynamic import or filesystem glob. Adding a new stack = add a file
 * here, then add one entry to the `ADAPTERS` array in the registry.
 */

export interface DetectionMatch {
  adapterId: string;
  displayName: string;
  /** 0..1; higher = more confident. */
  confidence: number;
  /** Human-readable evidence: matched file paths, package names, etc. */
  evidence: string[];
}

export interface Rule {
  id: string;
  language: string;
  severity: "error" | "warning" | "info";
  /** Self-contained Semgrep YAML fragment. */
  yaml: string;
}

export interface StackAdapter {
  id: string;
  displayName: string;
  match(rootPath: string): Promise<DetectionMatch[]> | DetectionMatch[];
  extraRules?(): Rule[];
}
