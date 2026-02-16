import type { Policy, ValidationResult, BudgetState } from "./types";

export function shouldKill(
  policy: Policy,
  result: ValidationResult,
  budgetState: BudgetState
): { kill: boolean; reason: string } {
  if (!policy.kill_switch.enabled) {
    return { kill: false, reason: "" };
  }

  // Critical blocklist violation
  if (
    policy.kill_switch.on_blocklist_critical &&
    !result.allowed &&
    result.severity === "critical"
  ) {
    return {
      kill: true,
      reason: `Critical policy violation: ${result.reason}`,
    };
  }

  // Budget breach with kill action
  if (
    policy.kill_switch.on_budget_breach &&
    budgetState.exceeded &&
    policy.budget.action_on_breach === "kill"
  ) {
    return {
      kill: true,
      reason: `Budget exceeded: ${budgetState.breach_reason}`,
    };
  }

  return { kill: false, reason: "" };
}

export function executeKill(reason: string, exitCode: number): never {
  process.stderr.write(`GUARDIAN KILL SWITCH: ${reason}. Session terminated.\n`);
  process.exit(exitCode);
}
