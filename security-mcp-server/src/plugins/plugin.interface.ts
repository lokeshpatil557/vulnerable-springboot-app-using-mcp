/**
 * Stack-detection plugin contract. Each plugin knows how to identify one
 * language / framework family and may also contribute extra Semgrep rule
 * fragments via `getExtraRules()`.
 *
 * Plugins are statically registered in `./plugin-registry.ts` — there is
 * **no dynamic import** or filesystem glob. Adding a new plugin = one
 * new file in this directory + one entry in the `PLUGINS` array.
 */

export interface DetectionMatch {
  id: string;
  displayName: string;
  confidence: number; // 0..1
  evidence: string[];
}

export interface ExtraRule {
  id: string;
  language: string;
  severity: "error" | "warning" | "info";
  yaml: string;
}

export interface StackPlugin {
  id: string;
  displayName: string;
  detect(rootPath: string): Promise<DetectionMatch[]> | DetectionMatch[];
  getExtraRules?(): ExtraRule[];
}
