/** Fallback plugin — always matches with very low confidence. */
import type { StackPlugin } from "./plugin.interface.js";

export const monolithPlugin: StackPlugin = {
  id: "monolith",
  displayName: "Monolith (fallback)",
  detect() {
    return [
      {
        id: "monolith",
        displayName: "Monolith (fallback)",
        confidence: 0.2,
        evidence: ["no specific architecture signal detected"],
      },
    ];
  },
};
