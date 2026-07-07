/**
 * Static catalogue of Semgrep rule packs the server knows about. Returned
 * by the `list_security_rules` tool — independent of whether Semgrep is
 * installed on the host.
 */

export interface SemgrepRulePack {
  id: string;
  name: string;
  description: string;
}

export const SEMGREP_RULE_PACKS: SemgrepRulePack[] = [
  { id: "p/default", name: "Default", description: "Semgrep default ruleset (broad coverage)." },
  { id: "p/owasp-top-ten", name: "OWASP Top 10", description: "OWASP Top 10 (2021) coverage." },
  { id: "p/security-audit", name: "Security audit", description: "Curated security-audit ruleset." },
  { id: "p/secrets", name: "Secrets", description: "Common cloud-provider and framework secrets." },
  { id: "p/javascript", name: "JavaScript", description: "Language pack: JavaScript / TypeScript." },
  { id: "p/typescript", name: "TypeScript", description: "Language pack: TypeScript." },
  { id: "p/python", name: "Python", description: "Language pack: Python." },
  { id: "p/java", name: "Java", description: "Language pack: Java." },
  { id: "p/csharp", name: "C#", description: "Language pack: C# / .NET." },
  { id: "p/go", name: "Go", description: "Language pack: Go." },
  { id: "p/rust", name: "Rust", description: "Language pack: Rust." },
  { id: "p/ruby", name: "Ruby", description: "Language pack: Ruby." },
  { id: "p/php", name: "PHP", description: "Language pack: PHP." },
];

export interface GitleaksRuleGroup {
  id: string;
  description: string;
}

export const GITLEAKS_RULE_GROUPS: GitleaksRuleGroup[] = [
  { id: "aws", description: "AWS access keys, secret keys, session tokens." },
  { id: "gcp", description: "Google Cloud service-account keys & OAuth tokens." },
  { id: "azure", description: "Azure subscription keys & connection strings." },
  { id: "github", description: "GitHub PATs, OAuth tokens, fine-grained tokens." },
  { id: "gitlab", description: "GitLab PATs, runner tokens." },
  { id: "stripe", description: "Stripe API keys (live & test)." },
  { id: "slack", description: "Slack bot/user tokens & webhooks." },
  { id: "private-key", description: "RSA, DSA, EC, OpenSSH private keys." },
  { id: "generic", description: "High-entropy strings & generic API key patterns." },
];

export interface TrivyCheckCategory {
  id: string;
  description: string;
}

export const TRIVY_CHECK_CATEGORIES: TrivyCheckCategory[] = [
  { id: "vuln", description: "Known CVEs in OS packages & language dependencies." },
  { id: "misconfig", description: "IaC misconfigurations (Terraform, K8s, Dockerfile, etc.)." },
  { id: "secret", description: "Secrets committed in IaC." },
  { id: "license", description: "License compliance issues (with --license-full)." },
  { id: "rbac", description: "Kubernetes RBAC risk assessment." },
];
