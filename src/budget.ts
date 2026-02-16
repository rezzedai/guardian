import * as fs from "fs";
import * as path from "path";
import type { Policy, BudgetState, CostFile } from "./types";

// In-memory action counter (per process)
let actionCount = 0;

export function checkBudget(policy: Policy, cwd: string): BudgetState {
  actionCount++;

  if (!policy.budget.enabled) {
    return { action_count: actionCount, session_cost_usd: null, exceeded: false, breach_reason: null };
  }

  // Check action count limit
  if (policy.budget.max_actions_per_session > 0 && actionCount > policy.budget.max_actions_per_session) {
    return {
      action_count: actionCount,
      session_cost_usd: null,
      exceeded: true,
      breach_reason: `Action limit exceeded: ${actionCount}/${policy.budget.max_actions_per_session}`,
    };
  }

  // Check cost limit via external cost file
  if (policy.budget.session_limit_usd !== null && policy.budget.cost_file) {
    const costPath = path.resolve(cwd, policy.budget.cost_file);
    try {
      if (fs.existsSync(costPath)) {
        const raw = fs.readFileSync(costPath, "utf-8");
        const costData = JSON.parse(raw) as CostFile;

        if (costData.total_cost_usd >= policy.budget.session_limit_usd) {
          return {
            action_count: actionCount,
            session_cost_usd: costData.total_cost_usd,
            exceeded: true,
            breach_reason: `Cost limit exceeded: $${costData.total_cost_usd.toFixed(2)}/$${policy.budget.session_limit_usd.toFixed(2)}`,
          };
        }

        return {
          action_count: actionCount,
          session_cost_usd: costData.total_cost_usd,
          exceeded: false,
          breach_reason: null,
        };
      }
    } catch {
      // Cost file unreadable — continue without cost tracking
    }
  }

  return { action_count: actionCount, session_cost_usd: null, exceeded: false, breach_reason: null };
}

export function getActionCount(): number {
  return actionCount;
}

export function resetActionCount(): void {
  actionCount = 0;
}
