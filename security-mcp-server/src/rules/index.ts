/**
 * Rule templates used by `proposeRemediation` when Semgrep does not provide
 * its own fix. Each template is keyed by a Semgrep-style `ruleId` (or a
 * prefix) and supplies either a literal or regex replacement.
 */

export type RemediationTemplate =
  | {
      kind: "literal-replace";
      ruleId: string;
      description: string;
      needle: string;
      replacement: string;
    }
  | {
      kind: "regex-replace";
      ruleId: string;
      description: string;
      pattern: string;
      replacement: string;
    };

const TEMPLATES: RemediationTemplate[] = [
  {
    kind: "literal-replace",
    ruleId: "java.lang.security.audit.formatted-sql-string",
    description: "Use parameterized queries (PreparedStatement) instead of string concatenation.",
    needle: "Statement st = conn.createStatement();",
    replacement: "PreparedStatement ps = conn.prepareStatement(\"...\");",
  },
  {
    kind: "literal-replace",
    ruleId: "javascript.lang.security.audit.detect-non-literal-regexp",
    description: "Avoid building RegExp from user input; use a literal pattern or escape.",
    needle: "new RegExp(",
    replacement: "new RegExp(/* escape user input */",
  },
  {
    kind: "regex-replace",
    ruleId: "python.lang.security.audit.formatted-sql-string",
    description: "Use parameterized queries with placeholders, not f-strings.",
    pattern: "f\"(SELECT|INSERT|UPDATE|DELETE)[^\"]*\\{[",
    replacement: 'cursor.execute("SELECT ... WHERE id = %s", (id,))',
  },
  {
    kind: "literal-replace",
    ruleId: "javascript.lang.security.audit.eval-detected",
    description: "Replace eval() with JSON.parse() or an explicit parser.",
    needle: "eval(",
    replacement: "JSON.parse(/* or use a safe parser */",
  },
];

const PREFIX_TEMPLATES: { prefix: string; template: RemediationTemplate }[] = [
  {
    prefix: "javascript.express.security.audit.express-open-redirect",
    template: {
      kind: "literal-replace",
      ruleId: "javascript.express.security.audit.express-open-redirect",
      description: "Validate the redirect target against an allowlist before res.redirect().",
      needle: "res.redirect(req.query.",
      replacement: "res.redirect(allowlisted(req.query.",
    },
  },
];

/** Find a template by exact ruleId, or by a known prefix. Returns null if none. */
export function lookupTemplate(ruleId: string): RemediationTemplate | null {
  for (const t of TEMPLATES) {
    if (t.ruleId === ruleId) return t;
  }
  for (const { prefix, template } of PREFIX_TEMPLATES) {
    if (ruleId.startsWith(prefix)) return template;
  }
  return null;
}

/** Return the list of all registered templates (for diagnostics). */
export function listTemplates(): RemediationTemplate[] {
  return [...TEMPLATES, ...PREFIX_TEMPLATES.map((p) => p.template)];
}
