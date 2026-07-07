import { getAdapters } from "./adapters/registry.js";
import type { DetectionMatch } from "./adapters/base.js";

/**
 * Run every registered stack adapter against `rootPath` and return a sorted
 * (by confidence desc), de-duplicated list of detection matches.
 */
export async function identifyCodebase(rootPath: string): Promise<DetectionMatch[]> {
  const adapters = getAdapters();
  const all: DetectionMatch[] = [];
  for (const adapter of adapters) {
    try {
      const matches = await adapter.match(rootPath);
      for (const m of matches) {
        // De-dupe by adapterId, keep highest confidence.
        const existing = all.find((x) => x.adapterId === m.adapterId);
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
      // An adapter that throws must not poison the rest.
    }
  }
  all.sort((a, b) => b.confidence - a.confidence);
  return all;
}
