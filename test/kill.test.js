import { describe, it } from "node:test";
import assert from "node:assert/strict";
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

import { shouldKill } from "../dist/kill.js";

const policy = JSON.parse(
  fs.readFileSync(path.join(__dirname, "../.guardian/policy.default.json"), "utf8")
);

describe("kill switch", () => {
  it("should return kill=true for critical blocklist violation", () => {
    const testPolicy = {
      ...policy,
      kill_switch: {
        ...policy.kill_switch,
        enabled: true,
        on_blocklist_critical: true,
      },
    };

    const result = {
      allowed: false,
      reason: "Destructive command",
      severity: "critical",
      pattern: "rm -rf",
      source: "blocklist",
    };

    const budgetState = {
      action_count: 1,
      session_cost_usd: null,
      exceeded: false,
      breach_reason: null,
    };

    const killCheck = shouldKill(testPolicy, result, budgetState);
    assert.equal(killCheck.kill, true);
    assert.ok(killCheck.reason.includes("Critical policy violation"));
  });

  it("should return kill=false for non-critical blocklist violation", () => {
    const testPolicy = {
      ...policy,
      kill_switch: {
        ...policy.kill_switch,
        enabled: true,
        on_blocklist_critical: true,
      },
    };

    const result = {
      allowed: false,
      reason: "High severity command",
      severity: "high",
      pattern: "git push --force",
      source: "blocklist",
    };

    const budgetState = {
      action_count: 1,
      session_cost_usd: null,
      exceeded: false,
      breach_reason: null,
    };

    const killCheck = shouldKill(testPolicy, result, budgetState);
    assert.equal(killCheck.kill, false);
  });

  it("should return kill=true for budget breach with kill action", () => {
    const testPolicy = {
      ...policy,
      kill_switch: {
        ...policy.kill_switch,
        enabled: true,
        on_budget_breach: true,
      },
      budget: {
        ...policy.budget,
        action_on_breach: "kill",
      },
    };

    const result = {
      allowed: true,
      reason: null,
      severity: null,
      pattern: null,
      source: null,
    };

    const budgetState = {
      action_count: 501,
      session_cost_usd: null,
      exceeded: true,
      breach_reason: "Action limit exceeded: 501/500",
    };

    const killCheck = shouldKill(testPolicy, result, budgetState);
    assert.equal(killCheck.kill, true);
    assert.ok(killCheck.reason.includes("Budget exceeded"));
  });

  it("should return kill=false when budget breach action is deny", () => {
    const testPolicy = {
      ...policy,
      kill_switch: {
        ...policy.kill_switch,
        enabled: true,
        on_budget_breach: true,
      },
      budget: {
        ...policy.budget,
        action_on_breach: "deny",
      },
    };

    const result = {
      allowed: false,
      reason: "Budget exceeded",
      severity: "high",
      pattern: null,
      source: "budget",
    };

    const budgetState = {
      action_count: 501,
      session_cost_usd: null,
      exceeded: true,
      breach_reason: "Action limit exceeded: 501/500",
    };

    const killCheck = shouldKill(testPolicy, result, budgetState);
    assert.equal(killCheck.kill, false);
  });

  it("should return kill=false when kill switch is disabled", () => {
    const testPolicy = {
      ...policy,
      kill_switch: {
        ...policy.kill_switch,
        enabled: false,
        on_blocklist_critical: true,
        on_budget_breach: true,
      },
    };

    const result = {
      allowed: false,
      reason: "Destructive command",
      severity: "critical",
      pattern: "rm -rf",
      source: "blocklist",
    };

    const budgetState = {
      action_count: 1,
      session_cost_usd: null,
      exceeded: false,
      breach_reason: null,
    };

    const killCheck = shouldKill(testPolicy, result, budgetState);
    assert.equal(killCheck.kill, false);
  });

  it("should return kill=false when on_blocklist_critical is disabled", () => {
    const testPolicy = {
      ...policy,
      kill_switch: {
        ...policy.kill_switch,
        enabled: true,
        on_blocklist_critical: false,
      },
    };

    const result = {
      allowed: false,
      reason: "Destructive command",
      severity: "critical",
      pattern: "rm -rf",
      source: "blocklist",
    };

    const budgetState = {
      action_count: 1,
      session_cost_usd: null,
      exceeded: false,
      breach_reason: null,
    };

    const killCheck = shouldKill(testPolicy, result, budgetState);
    assert.equal(killCheck.kill, false);
  });

  it("should return kill=false for allowed result with no budget breach", () => {
    const testPolicy = {
      ...policy,
      kill_switch: {
        ...policy.kill_switch,
        enabled: true,
        on_blocklist_critical: true,
        on_budget_breach: true,
      },
    };

    const result = {
      allowed: true,
      reason: null,
      severity: null,
      pattern: null,
      source: null,
    };

    const budgetState = {
      action_count: 1,
      session_cost_usd: null,
      exceeded: false,
      breach_reason: null,
    };

    const killCheck = shouldKill(testPolicy, result, budgetState);
    assert.equal(killCheck.kill, false);
  });
});
