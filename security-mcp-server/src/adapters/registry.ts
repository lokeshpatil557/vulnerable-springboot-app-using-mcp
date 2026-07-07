/**
 * Static, explicit registry of every StackAdapter. **No dynamic imports.**
 * To add a new framework: drop a new file in this directory, import it
 * here, and add it to the ADAPTERS array.
 */

import type { StackAdapter } from "./base.js";
import {
  javaSpringBoot,
  dotnetAspnet,
  express,
  nestjs,
  pythonDjango,
  pythonFlask,
  pythonFastapi,
  react,
  angular,
  vue,
  microservices,
  containerized,
  monolith,
} from "./detect.js";

const ADAPTERS: readonly StackAdapter[] = [
  javaSpringBoot,
  dotnetAspnet,
  express,
  nestjs,
  pythonDjango,
  pythonFlask,
  pythonFastapi,
  react,
  angular,
  vue,
  microservices,
  containerized,
  // Fallback — must be last so it never preempts a specific match.
  monolith,
];

export function getAdapters(): readonly StackAdapter[] {
  return ADAPTERS;
}
