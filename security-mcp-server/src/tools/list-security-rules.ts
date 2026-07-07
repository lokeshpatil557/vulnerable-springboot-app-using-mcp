import type { ToolContext, AnyMcpServer } from "./_shared.js";
import { auditWrap, ok } from "./_shared.js";
import {
  GITLEAKS_RULE_GROUPS,
  SEMGREP_RULE_PACKS,
  TRIVY_CHECK_CATEGORIES,
} from "../rules/semgrep-extra.js";

export function register(server: AnyMcpServer, _ctx: ToolContext): void {
  server.tool(
    "list_security_rules",
    "Enumerate the rule packs / categories known to each scanner. Static catalogue — independent of installed binaries.",
    {},
    async (args) =>
      auditWrap(_ctx, "list_security_rules", args, async () => {
        return ok({
          semgrep: SEMGREP_RULE_PACKS,
          gitleaks: GITLEAKS_RULE_GROUPS,
          trivy: TRIVY_CHECK_CATEGORIES,
        });
      }),
  );
}
