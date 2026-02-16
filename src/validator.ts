import * as path from "path";
import type { Policy, HookInput, ValidationResult, BudgetState } from "./types";
import { checkBlocklist } from "./blocklist";
import { checkBudget } from "./budget";
import { writeAuditEntry } from "./audit";
import { shouldKill, executeKill } from "./kill";

function checkAllowlist(input: HookInput, policy: Policy): boolean {
  // Command allowlist (exact match)
  if (input.tool_name === "Bash") {
    const command = (input.tool_input.command as string) ?? "";
    if (policy.allowlist.commands.includes(command)) return true;
  }

  // Path allowlist
  const filePath = (input.tool_input.file_path as string) ?? "";
  if (filePath && policy.allowlist.paths.some((p) => filePath.startsWith(p))) return true;

  // Domain allowlist (WebFetch)
  if (input.tool_name === "WebFetch") {
    const url = (input.tool_input.url as string) ?? "";
    try {
      const hostname = new URL(url).hostname;
      if (policy.allowlist.domains.includes(hostname)) return true;
    } catch {
      // Invalid URL — don't allowlist
    }
  }

  return false;
}

function checkScope(input: HookInput, policy: Policy, cwd: string): ValidationResult | null {
  // Only check scope for tools that reference file paths
  const filePath = (input.tool_input.file_path as string) ?? "";
  if (!filePath) return null;

  const resolved = path.resolve(cwd, filePath);

  // Check denied paths first
  for (const denied of policy.scope.denied_paths) {
    if (resolved.startsWith(denied)) {
      return {
        allowed: false,
        reason: `Path in denied scope: ${denied}`,
        severity: "high",
        pattern: denied,
        source: "scope",
      };
    }
  }

  // Check allowed paths
  if (!policy.scope.allow_outside_cwd) {
    const expandedAllowed = policy.scope.allowed_paths.map((p) =>
      p.replace("{cwd}", cwd)
    );

    const inAllowed = expandedAllowed.some((allowed) =>
      resolved.startsWith(allowed)
    );

    if (!inAllowed) {
      return {
        allowed: false,
        reason: `Path outside allowed scope: ${resolved}`,
        severity: "high",
        pattern: cwd,
        source: "scope",
      };
    }
  }

  return null;
}

export function validate(input: HookInput, policy: Policy, cwd: string): ValidationResult {
  // Passthrough mode
  if (policy.mode === "off") {
    return { allowed: true, reason: null, severity: null, pattern: null, source: null };
  }

  // 1. Allowlist check
  if (checkAllowlist(input, policy)) {
    return { allowed: true, reason: null, severity: null, pattern: null, source: "allowlist" };
  }

  // 2. Scope check
  const scopeResult = checkScope(input, policy, cwd);
  if (scopeResult) {
    if (policy.mode === "audit") {
      return { ...scopeResult, allowed: true };
    }
    return scopeResult;
  }

  // 3. Blocklist check
  const blocklistResult = checkBlocklist(input, policy);
  if (blocklistResult) {
    if (policy.mode === "audit") {
      return { ...blocklistResult, allowed: true };
    }
    return blocklistResult;
  }

  // 4. Budget check
  const budgetState = checkBudget(policy, cwd);
  if (budgetState.exceeded) {
    const budgetResult: ValidationResult = {
      allowed: false,
      reason: budgetState.breach_reason,
      severity: "high",
      pattern: null,
      source: "budget",
    };

    if (policy.mode === "audit") {
      return { ...budgetResult, allowed: true };
    }

    // Write audit before potential kill
    writeAuditEntry(input, budgetResult, policy, cwd, {
      remaining_usd: budgetState.session_cost_usd !== null && policy.budget.session_limit_usd !== null
        ? policy.budget.session_limit_usd - budgetState.session_cost_usd
        : null,
      action_count: budgetState.action_count,
    });

    // Kill check
    const killCheck = shouldKill(policy, budgetResult, budgetState);
    if (killCheck.kill) {
      executeKill(killCheck.reason, policy.kill_switch.exit_code);
    }

    return budgetResult;
  }

  // All checks passed
  return { allowed: true, reason: null, severity: null, pattern: null, source: null };
}

export function validateAndAudit(input: HookInput, policy: Policy, cwd: string): ValidationResult {
  const result = validate(input, policy, cwd);
  const budgetState = checkBudget(policy, cwd);

  // Write audit entry
  writeAuditEntry(input, result, policy, cwd, {
    remaining_usd: budgetState.session_cost_usd !== null && policy.budget.session_limit_usd !== null
      ? policy.budget.session_limit_usd - budgetState.session_cost_usd
      : null,
    action_count: budgetState.action_count,
  });

  // Kill switch check (for non-budget violations — budget kill is handled in validate)
  if (!result.allowed && result.severity === "critical") {
    const killCheck = shouldKill(policy, result, budgetState);
    if (killCheck.kill) {
      executeKill(killCheck.reason, policy.kill_switch.exit_code);
    }
  }

  return result;
}
