// vitest setup — silences pino (otherwise tests spam stderr) and
// points REPO_ROOT at a temp fixture repo for any test that needs it.
import { pino } from "pino";

const silentLogger = pino({ level: "silent" });

// Expose a single shared logger for tests.
(globalThis as Record<string, unknown>).__silentLogger = silentLogger;
