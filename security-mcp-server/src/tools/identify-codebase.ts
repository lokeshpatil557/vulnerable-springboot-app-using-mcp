/**
 * `identify_codebase` — detect languages, frameworks, and architecture for
 * a path inside the allowed repository root.
 *
 * Input:  { path?: string }   (defaults to ctx.repoRoot)
 *
 * Output: {
 *   path, repoRoot, gitRoot,
 *   languages:   [{ id, displayName, evidence: string[] }],   // by file extension
 *   frameworks:  [{ id, displayName, confidence, evidence }], // existing adapter matches
 *   architecture:[{ id, displayName, confidence, evidence }], // monolith / microservices / api / frontend / containerized
 *   scanners:    [{ id, displayName, available, version?, reason?,
 *                   recommended, reasonToRun, priority }],    // which scanners to run, in what order
 *   detectedAt: string,
 * }
 */
import { readdir, readFile, stat } from "node:fs/promises";
import { join, relative } from "node:path";
import type { ToolContext, AnyMcpServer } from "./_shared.js";
import { z, auditWrap, ok } from "./_shared.js";
import { identifyCodebase } from "../stack-detect.js";
import { assertInsideRepo, relativeToRepo } from "../paths.js";
import { gitRevParseShowToplevel } from "../utils/git.js";
import { PathEscapeError } from "../security/path-safety.js";
import type { ScannerRegistry } from "../scanners/registry.js";

// --- Types ----------------------------------------------------------------

export interface LanguageMatch {
  id: string;
  displayName: string;
  /** Matched file paths (repo-relative), capped. */
  evidence: string[];
}

export interface ArchitectureMatch {
  id: string;
  displayName: string;
  /** 0..1. */
  confidence: number;
  evidence: string[];
}

/** One scanner's status + recommendation for the detected codebase. */
export interface ScannerRecommendation {
  id: "semgrep" | "gitleaks" | "trivy";
  displayName: string;
  /** True iff the binary is on PATH (or resolved via env override). */
  available: boolean;
  /** Reported by `--version` when available. */
  version?: string;
  /** Populated when `available: false` — human-readable reason. */
  reason?: string;
  /** True if the orchestrator recommends running this scanner on the detected stack. */
  recommended: boolean;
  /** Why this scanner is or isn't recommended, with concrete evidence. */
  reasonToRun: string;
  /**
   * Sort key (lower = run earlier). Missing or non-finite = "not run".
   *  - 1 = highest priority (always run when present)
   *  - 2 = run if any relevant signal present
   *  - 3 = run only when explicitly justified
   */
  priority: 1 | 2 | 3 | null;
}

export interface IdentifyCodebaseResult {
  path: string;
  repoRoot: string;
  gitRoot: string | null;
  languages: LanguageMatch[];
  frameworks: { id: string; displayName: string; confidence: number; evidence: string[] }[];
  architecture: ArchitectureMatch[];
  scanners: ScannerRecommendation[];
  detectedAt: string;
}

// --- Language detection (by file extension) -------------------------------

const LANGUAGE_EXTENSIONS: Record<string, string> = {
  ".js": "javascript",
  ".mjs": "javascript",
  ".cjs": "javascript",
  ".jsx": "javascript",
  ".ts": "typescript",
  ".tsx": "typescript",
  ".py": "python",
  ".java": "java",
  ".kt": "kotlin",
  ".scala": "scala",
  ".go": "go",
  ".rb": "ruby",
  ".php": "php",
  ".cs": "csharp",
  ".vb": "vbnet",
  ".cpp": "cpp",
  ".c": "c",
  ".h": "c",
  ".hpp": "cpp",
  ".rs": "rust",
  ".swift": "swift",
  ".m": "objc",
  ".mm": "objc",
  ".sh": "shell",
  ".bash": "shell",
  ".ps1": "powershell",
  ".html": "html",
  ".htm": "html",
  ".css": "css",
  ".scss": "scss",
  ".sass": "sass",
  ".less": "less",
  ".vue": "vue",
  ".svelte": "svelte",
  ".dart": "dart",
  ".lua": "lua",
  ".r": "r",
  ".sql": "sql",
  ".yaml": "yaml",
  ".yml": "yaml",
  ".json": "json",
  ".xml": "xml",
  ".md": "markdown",
};

const SKIP_DIRS = new Set([
  "node_modules",
  ".git",
  "target",
  "build",
  "dist",
  ".next",
  ".nuxt",
  "out",
  "coverage",
  ".venv",
  "venv",
  "__pycache__",
  ".idea",
  ".vscode",
  "vendor",
  "bin",
  "obj",
]);

/**
 * Bounded directory walk that counts file extensions and returns the
 * matching languages. `maxFiles` is a hard cap to keep large repos fast.
 */
export async function detectLanguages(
  root: string,
  maxFiles = 20_000,
  maxDepth = 8,
): Promise<LanguageMatch[]> {
  const counts = new Map<string, { files: string[] }>();
  const stack: { dir: string; depth: number }[] = [{ dir: root, depth: 0 }];
  let visited = 0;

  while (stack.length && visited < maxFiles) {
    const { dir, depth } = stack.pop()!;
    if (depth > maxDepth) continue;
    let entries: import("node:fs").Dirent[];
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      if (visited >= maxFiles) break;
      const full = join(dir, e.name);
      if (e.isDirectory()) {
        if (SKIP_DIRS.has(e.name)) continue;
        stack.push({ dir: full, depth: depth + 1 });
        continue;
      }
      if (!e.isFile()) continue;
      visited++;
      const lower = e.name.toLowerCase();
      const dot = lower.lastIndexOf(".");
      if (dot < 0) continue;
      const ext = lower.slice(dot);
      const lang = LANGUAGE_EXTENSIONS[ext];
      if (!lang) continue;
      const entry = counts.get(lang) ?? { files: [] };
      if (entry.files.length < 5) entry.files.push(relative(root, full));
      counts.set(lang, entry);
    }
  }

  return [...counts.entries()]
    .map(([id, v]): LanguageMatch => ({
      id,
      displayName: id.charAt(0).toUpperCase() + id.slice(1),
      evidence: v.files,
    }))
    .sort((a, b) => a.id.localeCompare(b.id));
}

// --- Architecture detection ----------------------------------------------

/** Best-effort detection of API-serving frameworks: Express, NestJS, Spring MVC, ASP.NET, Django REST, FastAPI, Flask. */
const API_FRAMEWORK_IDS = new Set([
  "express",
  "nestjs",
  "java-spring-boot",
  "dotnet-aspnet",
  "python-django",
  "python-flask",
  "python-fastapi",
]);

/** Best-effort detection of frontend SPA frameworks: React, Angular, Vue. */
const FRONTEND_FRAMEWORK_IDS = new Set(["react", "angular", "vue"]);

interface RawCounts {
  dockerfiles: number;
  composeFiles: string[];
  composeServiceCounts: number[];
  serviceRoots: number;
  hasFrontendDirs: boolean;
}

/** Count concrete signals used by architecture detectors. Bounded to keep large repos fast. */
async function collectArchitectureSignals(root: string, maxDepth = 4): Promise<RawCounts> {
  const out: RawCounts = {
    dockerfiles: 0,
    composeFiles: [],
    composeServiceCounts: [],
    serviceRoots: 0,
    hasFrontendDirs: false,
  };
  const stack: { dir: string; depth: number }[] = [{ dir: root, depth: 0 }];

  while (stack.length) {
    const { dir, depth } = stack.pop()!;
    if (depth > maxDepth) continue;
    let entries: import("node:fs").Dirent[];
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    const subdirs: string[] = [];
    for (const e of entries) {
      const full = join(dir, e.name);
      if (e.isDirectory()) {
        if (SKIP_DIRS.has(e.name)) continue;
        if (e.name === "src" || e.name === "public" || e.name === "client" || e.name === "web" || e.name === "frontend") {
          out.hasFrontendDirs = true;
        }
        subdirs.push(full);
        continue;
      }
      if (!e.isFile()) continue;
      if (e.name === "Dockerfile" || e.name === "Dockerfile.prod") {
        out.dockerfiles++;
        continue;
      }
      if (
        e.name === "docker-compose.yml" ||
        e.name === "docker-compose.yaml" ||
        e.name === "compose.yaml" ||
        e.name === "compose.yml"
      ) {
        out.composeFiles.push(full);
        try {
          const data = await readFile(full, "utf8");
          const services = (data.match(/^\s{2}\w[\w-]*:\s*$/gm) ?? []).length;
          out.composeServiceCounts.push(services);
        } catch {
          // ignore
        }
      }
    }
    // First-level service-root sniff: any direct subdir that looks buildable.
    if (depth === 0) {
      for (const sub of subdirs) {
        for (const manifest of ["pom.xml", "package.json", "go.mod", "build.gradle"]) {
          try {
            await stat(join(sub, manifest));
            out.serviceRoots++;
            break;
          } catch {
            // not this one
          }
        }
      }
    }
    for (const s of subdirs) stack.push({ dir: s, depth: depth + 1 });
  }
  return out;
}

/**
 * Roll up the plugin matches + raw signal counts into architecture labels.
 * Multiple architectures can apply (e.g. "containerized" + "api" + "frontend").
 */
export async function detectArchitecture(
  root: string,
  frameworkIds: Set<string>,
): Promise<ArchitectureMatch[]> {
  const sig = await collectArchitectureSignals(root);
  const matches: ArchitectureMatch[] = [];

  // 1. Containerized — Dockerfile + compose / k8s.
  const containerEvidence: string[] = [];
  let containerConfidence = 0;
  if (sig.dockerfiles >= 1) {
    containerConfidence += 0.5;
    containerEvidence.push(`${sig.dockerfiles} Dockerfile${sig.dockerfiles > 1 ? "s" : ""}`);
  }
  if (sig.composeFiles.length >= 1) {
    containerConfidence += 0.3;
    containerEvidence.push(sig.composeFiles.map((p) => relative(root, p)).join(", "));
  }
  if (containerConfidence > 0) {
    matches.push({
      id: "containerized",
      displayName: "Containerized",
      confidence: Math.min(containerConfidence, 0.95),
      evidence: containerEvidence,
    });
  }

  // 2. Microservices — multiple Dockerfiles / compose services / service roots.
  const msEvidence: string[] = [];
  let msConfidence = 0;
  if (sig.dockerfiles >= 3) {
    msConfidence += 0.4;
    msEvidence.push(`${sig.dockerfiles} Dockerfiles`);
  } else if (sig.dockerfiles >= 2) {
    msConfidence += 0.2;
    msEvidence.push(`${sig.dockerfiles} Dockerfiles`);
  }
  const maxServices = sig.composeServiceCounts.length ? Math.max(...sig.composeServiceCounts) : 0;
  if (maxServices >= 3) {
    msConfidence += 0.4;
    msEvidence.push(`docker-compose with ${maxServices} services`);
  } else if (maxServices >= 2) {
    msConfidence += 0.2;
    msEvidence.push(`docker-compose with ${maxServices} services`);
  }
  if (sig.serviceRoots >= 3) {
    msConfidence += 0.4;
    msEvidence.push(`${sig.serviceRoots} buildable service roots`);
  } else if (sig.serviceRoots >= 2) {
    msConfidence += 0.2;
    msEvidence.push(`${sig.serviceRoots} buildable service roots`);
  }
  if (msConfidence > 0) {
    matches.push({
      id: "microservices",
      displayName: "Microservices",
      confidence: Math.min(msConfidence, 0.99),
      evidence: msEvidence,
    });
  }

  // 3. API — any backend framework detected.
  const apiHits = [...frameworkIds].filter((id) => API_FRAMEWORK_IDS.has(id));
  if (apiHits.length > 0) {
    matches.push({
      id: "api",
      displayName: "API",
      confidence: Math.min(0.6 + apiHits.length * 0.1, 0.95),
      evidence: apiHits.map((id) => `framework: ${id}`),
    });
  }

  // 4. Frontend — any frontend framework or frontend-style directories.
  const feHits = [...frameworkIds].filter((id) => FRONTEND_FRAMEWORK_IDS.has(id));
  const feEvidence = [
    ...feHits.map((id) => `framework: ${id}`),
    ...(sig.hasFrontendDirs && feHits.length === 0 ? ["frontend directory layout (src/, public/, client/, web/)"] : []),
  ];
  if (feEvidence.length > 0) {
    matches.push({
      id: "frontend",
      displayName: "Frontend",
      confidence: feHits.length > 0 ? Math.min(0.7 + feHits.length * 0.1, 0.95) : 0.4,
      evidence: feEvidence,
    });
  }

  // 5. Monolith — single service root and no microservices signal.
  // Only emit if a backend framework was detected AND nothing indicates microservices.
  if (
    apiHits.length > 0 &&
    msConfidence === 0 &&
    sig.serviceRoots <= 1 &&
    sig.dockerfiles <= 1
  ) {
    matches.push({
      id: "monolith",
      displayName: "Monolith",
      confidence: 0.7,
      evidence: ["single service root, no microservices signals"],
    });
  }

  // Stable, predictable order.
  matches.sort((a, b) => a.id.localeCompare(b.id));
  return matches;
}

// --- Scanner recommendation -----------------------------------------------

/** Manifests whose presence means trivy is worth running. */
const TRIVY_RELEVANT_MANIFESTS = new Set([
  "pom.xml",
  "build.gradle",
  "build.gradle.kts",
  "package.json",
  "package-lock.json",
  "yarn.lock",
  "pnpm-lock.yaml",
  "requirements.txt",
  "Pipfile",
  "Pipfile.lock",
  "pyproject.toml",
  "go.mod",
  "go.sum",
  "Gemfile",
  "Gemfile.lock",
  "composer.json",
  "composer.lock",
  "Cargo.toml",
  "Cargo.lock",
]);

/** Language ids that count as "source code" for semgrep recommendation. */
const SOURCE_LANGUAGE_IDS = new Set([
  "javascript",
  "typescript",
  "python",
  "java",
  "kotlin",
  "scala",
  "go",
  "ruby",
  "php",
  "csharp",
  "vbnet",
  "cpp",
  "c",
  "rust",
  "swift",
  "objc",
  "shell",
  "powershell",
  "lua",
  "dart",
]);

/**
 * Walk `root` one level deep and collect any manifests that look like
 * language package / lock files. Bounded — first level only is enough
 * for a recommendation.
 */
async function sniffManifests(root: string): Promise<string[]> {
  const out: string[] = [];
  let entries: import("node:fs").Dirent[];
  try {
    entries = await readdir(root, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const e of entries) {
    if (!e.isFile()) continue;
    if (TRIVY_RELEVANT_MANIFESTS.has(e.name)) out.push(e.name);
  }
  return out;
}

/**
 * Build a `ScannerRecommendation` for every registered scanner, given
 * the detected languages, frameworks, and architecture.
 *
 * Probes `isAvailable()` in parallel — each probe is short (`--version`
 * with a 5s timeout) and never throws. Unavailable scanners are still
 * included so the caller can see what's missing.
 */
export async function recommendScanners(
  root: string,
  scanners: ScannerRegistry,
  detected: {
    languages: LanguageMatch[];
    frameworkIds: Set<string>;
    architecture: ArchitectureMatch[];
  },
): Promise<ScannerRecommendation[]> {
  const hasSourceCode = detected.languages.some((l) => SOURCE_LANGUAGE_IDS.has(l.id));
  const hasConfig = detected.languages.some((l) => l.id === "json" || l.id === "yaml" || l.id === "xml");
  const hasDockerfile = detected.architecture.some((a) => a.id === "containerized");
  const isApi = detected.architecture.some((a) => a.id === "api");
  const manifests = await sniffManifests(root);
  const hasManifest = manifests.length > 0;

  // Probe all three scanners in parallel. `isAvailable` never throws —
  // it returns `{ ok: false, reason }` on failure — so Promise.allSettled
  // is belt-and-braces.
  const [semgrepAvail, gitleaksAvail, trivyAvail] = await Promise.all([
    scanners.semgrep.isAvailable(),
    scanners.gitleaks.isAvailable(),
    scanners.trivy.isAvailable(),
  ]);

  // --- Semgrep: SAST over source code. Always recommended if any source. ---
  let semgrepRec: ScannerRecommendation;
  if (!hasSourceCode) {
    semgrepRec = {
      id: "semgrep",
      displayName: scanners.semgrep.displayName,
      available: semgrepAvail.ok,
      version: semgrepAvail.version,
      reason: semgrepAvail.reason,
      recommended: false,
      reasonToRun:
        "no source-code files detected (only configs / docs / data) — SAST has nothing to scan",
      priority: null,
    };
  } else {
    const langs = detected.languages.filter((l) => SOURCE_LANGUAGE_IDS.has(l.id)).map((l) => l.id);
    semgrepRec = {
      id: "semgrep",
      displayName: scanners.semgrep.displayName,
      available: semgrepAvail.ok,
      version: semgrepAvail.version,
      reason: semgrepAvail.reason,
      recommended: true,
      reasonToRun: `source code detected: ${langs.join(", ")}`,
      priority: 1,
    };
  }

  // --- Gitleaks: secret detection. Always recommended on a real codebase. ---
  let gitleaksRec: ScannerRecommendation;
  if (!hasSourceCode && !hasConfig) {
    gitleaksRec = {
      id: "gitleaks",
      displayName: scanners.gitleaks.displayName,
      available: gitleaksAvail.ok,
      version: gitleaksAvail.version,
      reason: gitleaksAvail.reason,
      recommended: false,
      reasonToRun: "no source or config files detected — secret scan has nothing meaningful to do",
      priority: null,
    };
  } else {
    const signals: string[] = [];
    if (hasSourceCode) signals.push("source code present");
    if (hasConfig) signals.push("config / manifest files present");
    gitleaksRec = {
      id: "gitleaks",
      displayName: scanners.gitleaks.displayName,
      available: gitleaksAvail.ok,
      version: gitleaksAvail.version,
      reason: gitleaksAvail.reason,
      recommended: true,
      reasonToRun: signals.join("; "),
      priority: 1,
    };
  }

  // --- Trivy: vuln / IaC / container / SBOM. Recommended on manifests
  //     or containerized code; lower priority otherwise. ---
  let trivyRec: ScannerRecommendation;
  if (hasManifest) {
    trivyRec = {
      id: "trivy",
      displayName: scanners.trivy.displayName,
      available: trivyAvail.ok,
      version: trivyAvail.version,
      reason: trivyAvail.reason,
      recommended: true,
      reasonToRun: `dependency manifest${manifests.length > 1 ? "s" : ""} detected: ${manifests.join(", ")}`,
      priority: 1,
    };
  } else if (hasDockerfile || isApi) {
    trivyRec = {
      id: "trivy",
      displayName: scanners.trivy.displayName,
      available: trivyAvail.ok,
      version: trivyAvail.version,
      reason: trivyAvail.reason,
      recommended: true,
      reasonToRun: hasDockerfile
        ? "containerized architecture — image / IaC scan useful"
        : "API architecture — filesystem vuln scan is reasonable",
      priority: 2,
    };
  } else {
    trivyRec = {
      id: "trivy",
      displayName: scanners.trivy.displayName,
      available: trivyAvail.ok,
      version: trivyAvail.version,
      reason: trivyAvail.reason,
      recommended: false,
      reasonToRun: "no manifests, no Dockerfile, no API surface — trivy has limited value here",
      priority: 3,
    };
  }

  return [semgrepRec, gitleaksRec, trivyRec];
}

// --- Tool registration ----------------------------------------------------

export function register(server: AnyMcpServer, ctx: ToolContext): void {
  server.tool(
    "identify_codebase",
    "Detect the technology stack of a path inside the allowed repository root. " +
      "Returns languages (by file extension), frameworks (manifest-based), " +
      "architecture (monolith / microservices / api / frontend / containerized), " +
      "and per-scanner recommendations (semgrep, gitleaks, trivy) with availability and priority.",
    {
      path: z.string().min(1).max(4096).optional(),
    },
    async (args) =>
      auditWrap(ctx, "identify_codebase", args, async () => {
        const a = args as { path?: string };

        // 1. Sandbox: resolve and assert the path is inside the allowed repo root.
        //    `assertInsideRepo` throws `PathEscapeError` on escape, which
        //    `auditWrap` records with code "path_escape".
        const inputPath = a.path && a.path.length > 0 ? a.path : ".";
        let abs: string;
        try {
          abs = assertInsideRepo(ctx.repoRoot, inputPath);
        } catch (err) {
          if (err instanceof PathEscapeError) {
            throw err;
          }
          throw err;
        }
        // If the path is a file, scan its containing directory instead — file
        // extension analysis needs a directory tree.
        let scanRoot = abs;
        try {
          const s = await stat(abs);
          if (s.isFile()) scanRoot = join(abs, "..");
        } catch {
          // Missing path — keep the original; detectors will simply find nothing.
        }

        // 2. Detect Git repository root (via `git rev-parse --show-toplevel`).
        const gitRoot = await gitRevParseShowToplevel(scanRoot);

        // 3. Frameworks via existing adapters (manifest-based).
        const frameworkMatches = await identifyCodebase(scanRoot);
        const frameworks = frameworkMatches.map((m) => ({
          id: m.adapterId,
          displayName: m.displayName,
          confidence: m.confidence,
          evidence: m.evidence,
        }));
        const frameworkIds = new Set(frameworks.map((f) => f.id));

        // 4. Languages by file extension.
        const languages = await detectLanguages(scanRoot);

        // 5. Architecture roll-up.
        const architecture = await detectArchitecture(scanRoot, frameworkIds);

        // 6. Per-scanner recommendations. Probes availability in parallel and
        //    assigns a priority based on the detected languages / frameworks /
        //    architecture.
        const scanners = await recommendScanners(scanRoot, ctx.scanners, {
          languages,
          frameworkIds,
          architecture,
        });

        const result: IdentifyCodebaseResult = {
          path: relativeToRepo(ctx.repoRoot, abs),
          repoRoot: ctx.repoRoot,
          gitRoot,
          languages,
          frameworks,
          architecture,
          scanners,
          detectedAt: new Date().toISOString(),
        };
        return ok(result as unknown as Record<string, unknown>);
      }),
  );
}
