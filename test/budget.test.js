import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

import { checkBudget, getActionCount, resetActionCount } from "../dist/budget.js";

const policy = JSON.parse(
  fs.readFileSync(path.join(__dirname, "../.guardian/policy.default.json"), "utf8")
);

describe("budget", () => {
  let tempDir;

  beforeEach(() => {
    resetActionCount();
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-budget-"));
  });

  afterEach(() => {
    if (tempDir && fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("should pass when budget is disabled", () => {
    const testPolicy = {
      ...policy,
      budget: {
        ...policy.budget,
        enabled: false,
      },
    };

    const result = checkBudget(testPolicy, tempDir);
    assert.equal(result.exceeded, false);
    assert.equal(result.breach_reason, null);
    assert.equal(result.action_count, 1);
  });

  it("should track action count", () => {
    const testPolicy = {
      ...policy,
      budget: {
        ...policy.budget,
        enabled: true,
        max_actions_per_session: 100,
      },
    };

    checkBudget(testPolicy, tempDir);
    assert.equal(getActionCount(), 1);

    checkBudget(testPolicy, tempDir);
    assert.equal(getActionCount(), 2);

    checkBudget(testPolicy, tempDir);
    assert.equal(getActionCount(), 3);
  });

  it("should exceed when action limit is reached", () => {
    const testPolicy = {
      ...policy,
      budget: {
        ...policy.budget,
        enabled: true,
        max_actions_per_session: 3,
      },
    };

    let result = checkBudget(testPolicy, tempDir);
    assert.equal(result.exceeded, false);

    result = checkBudget(testPolicy, tempDir);
    assert.equal(result.exceeded, false);

    result = checkBudget(testPolicy, tempDir);
    assert.equal(result.exceeded, false);

    // Fourth action should exceed
    result = checkBudget(testPolicy, tempDir);
    assert.equal(result.exceeded, true);
    assert.ok(result.breach_reason.includes("Action limit exceeded"));
    assert.equal(result.action_count, 4);
  });

  it("should reset action count", () => {
    const testPolicy = {
      ...policy,
      budget: {
        ...policy.budget,
        enabled: true,
        max_actions_per_session: 100,
      },
    };

    checkBudget(testPolicy, tempDir);
    checkBudget(testPolicy, tempDir);
    assert.equal(getActionCount(), 2);

    resetActionCount();
    assert.equal(getActionCount(), 0);

    checkBudget(testPolicy, tempDir);
    assert.equal(getActionCount(), 1);
  });

  it("should track cost from cost file", () => {
    const costFile = path.join(tempDir, "costs.json");
    const costData = {
      session_id: "test-session",
      total_cost_usd: 1.50,
      last_updated: new Date().toISOString(),
    };

    fs.writeFileSync(costFile, JSON.stringify(costData));

    const testPolicy = {
      ...policy,
      budget: {
        ...policy.budget,
        enabled: true,
        max_actions_per_session: 1000,
        session_limit_usd: 5.0,
        cost_file: "costs.json",
      },
    };

    const result = checkBudget(testPolicy, tempDir);
    assert.equal(result.exceeded, false);
    assert.equal(result.session_cost_usd, 1.50);
  });

  it("should exceed when cost limit is breached", () => {
    const costFile = path.join(tempDir, "costs.json");
    const costData = {
      session_id: "test-session",
      total_cost_usd: 10.0,
      last_updated: new Date().toISOString(),
    };

    fs.writeFileSync(costFile, JSON.stringify(costData));

    const testPolicy = {
      ...policy,
      budget: {
        ...policy.budget,
        enabled: true,
        max_actions_per_session: 1000,
        session_limit_usd: 5.0,
        cost_file: "costs.json",
      },
    };

    const result = checkBudget(testPolicy, tempDir);
    assert.equal(result.exceeded, true);
    assert.ok(result.breach_reason.includes("Cost limit exceeded"));
    assert.equal(result.session_cost_usd, 10.0);
  });

  it("should handle missing cost file gracefully", () => {
    const testPolicy = {
      ...policy,
      budget: {
        ...policy.budget,
        enabled: true,
        max_actions_per_session: 100,
        session_limit_usd: 5.0,
        cost_file: "non-existent.json",
      },
    };

    const result = checkBudget(testPolicy, tempDir);
    assert.equal(result.exceeded, false);
    assert.equal(result.session_cost_usd, null);
  });

  it("should handle corrupted cost file gracefully", () => {
    const costFile = path.join(tempDir, "bad-costs.json");
    fs.writeFileSync(costFile, "{ invalid json");

    const testPolicy = {
      ...policy,
      budget: {
        ...policy.budget,
        enabled: true,
        max_actions_per_session: 100,
        session_limit_usd: 5.0,
        cost_file: "bad-costs.json",
      },
    };

    const result = checkBudget(testPolicy, tempDir);
    assert.equal(result.exceeded, false);
    assert.equal(result.session_cost_usd, null);
  });

  it("should not check cost when session_limit_usd is null", () => {
    const costFile = path.join(tempDir, "costs.json");
    const costData = {
      session_id: "test-session",
      total_cost_usd: 100.0,
      last_updated: new Date().toISOString(),
    };

    fs.writeFileSync(costFile, JSON.stringify(costData));

    const testPolicy = {
      ...policy,
      budget: {
        ...policy.budget,
        enabled: true,
        max_actions_per_session: 1000,
        session_limit_usd: null,
        cost_file: "costs.json",
      },
    };

    const result = checkBudget(testPolicy, tempDir);
    assert.equal(result.exceeded, false);
    assert.equal(result.session_cost_usd, null);
  });
});
