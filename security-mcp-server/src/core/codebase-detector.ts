/**
 * Codebase detection — identify the technology stack of the repository by
 * running every registered plugin and aggregating their confidence scores.
 *
 * Plugins live in `../plugins/*.plugin.ts` and are statically registered in
 * `../plugins/plugin-registry.ts`. No dynamic imports.
 */

import type { DetectionMatch } from "../plugins/plugin.interface.js";
import { getPlugins } from "../plugins/plugin-registry.js";

export interface CodebaseReport {
  repoRoot: string;
  matches: DetectionMatch[];
  detectedAt: string;
}

/**
 * Run every plugin against `rootPath` and return a sorted, de-duplicated
 * list of detection matches. An adapter that throws is silently skipped —
 * detection failures must not poison the rest of the response.
 */
export async function detectCodebase(rootPath: string): Promise<DetectionMatch[]> {
  const plugins = getPlugins();
  const all: DetectionMatch[] = [];
  for (const plugin of plugins) {
    try {
      const matches = await plugin.detect(rootPath);
      for (const m of matches) {
        const existing = all.find((x) => x.id === m.id);
        if (!existing || m.confidence > existing.confidence) {
          if (existing) {
            const idx = all.indexOf(existing);
            all[idx] = m;
          } else {
            all.push(m);
          }
        }
      }
    } catch {
      // ignore
    }
  }
  all.sort((a, b) => b.confidence - a.confidence);
  return all;
}

/** Build a full CodebaseReport (idempotent). */
export async function buildCodebaseReport(rootPath: string): Promise<CodebaseReport> {
  return {
    repoRoot: rootPath,
    matches: await detectCodebase(rootPath),
    detectedAt: new Date().toISOString(),
  };
}
