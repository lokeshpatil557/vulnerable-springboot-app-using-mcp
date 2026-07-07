/**
 * Static, explicit registry of every StackPlugin. **No dynamic imports.**
 * To add a new stack: drop a new file in this directory, import it here,
 * and add it to the PLUGINS array.
 */

import type { StackPlugin } from "./plugin.interface.js";
import { javaSpringPlugin } from "./java-spring.plugin.js";
import { dotnetPlugin } from "./dotnet.plugin.js";
import { nodePlugin } from "./node.plugin.js";
import { pythonPlugin } from "./python.plugin.js";
import { frontendPlugin } from "./frontend.plugin.js";
import { containerPlugin } from "./container.plugin.js";
import { monolithPlugin } from "./monolith.plugin.js";

const PLUGINS: readonly StackPlugin[] = [
  javaSpringPlugin,
  dotnetPlugin,
  nodePlugin,
  pythonPlugin,
  frontendPlugin,
  containerPlugin,
  // Fallback — must be last so it never preempts a specific match.
  monolithPlugin,
];

export function getPlugins(): readonly StackPlugin[] {
  return PLUGINS;
}
