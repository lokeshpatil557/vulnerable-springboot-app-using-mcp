import { build } from "esbuild";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));

await build({
  entryPoints: [resolve(here, "src/index.ts")],
  outfile: resolve(here, "dist/index.js"),
  bundle: true,
  platform: "node",
  target: "node20",
  format: "esm",
  // Keep these as external so the user's installed Node resolves them at runtime.
  external: [
    "@modelcontextprotocol/sdk",
    "execa",
    "pino",
    "p-limit",
    "zod",
    "diff",
  ],
  banner: {
    // Allow `import.meta.url` lookups under ESM without breaking CommonJS shims.
    js: "import { createRequire as __cR } from 'module'; const require = __cR(import.meta.url);",
  },
  sourcemap: true,
  minify: false,
  logLevel: "info",
});
