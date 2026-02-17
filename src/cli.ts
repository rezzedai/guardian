#!/usr/bin/env node

import * as fs from "fs";
import * as path from "path";
import { loadPolicy, getDefaultPolicyPath } from "./policy";
import { validate } from "./validator";
import { verifyAuditChain, getAuditSummary } from "./audit";
import { handleHook } from "./hook";
import type { HookInput } from "./types";

function printUsage(): void {
  console.log(`guardian — safety rails for AI agent sessions

Usage:
  guardian init                    Initialize Guardian in this project
  guardian validate                Hook mode: read tool call from stdin, validate
  guardian check                   Validate policy file
  guardian audit verify            Verify audit trail integrity
  guardian audit summary           Show audit summary
  guardian test "<command>"        Dry-run a command against policy
  guardian budget                  Show current budget status
  -h, --help                      Show this help`);
}

function cmdInit(): void {
  const cwd = process.cwd();
  const guardianDir = path.join(cwd, ".guardian");
  const policyDest = path.join(guardianDir, "policy.json");

  // Create .guardian directory
  if (!fs.existsSync(guardianDir)) {
    fs.mkdirSync(guardianDir, { recursive: true });
  }

  // Copy default policy
  if (fs.existsSync(policyDest)) {
    console.log(".guardian/policy.json already exists. Skipping.");
  } else {
    const defaultPolicy = getDefaultPolicyPath();
    if (fs.existsSync(defaultPolicy)) {
      fs.copyFileSync(defaultPolicy, policyDest);
      console.log("Created .guardian/policy.json with default policy.");
    } else {
      // Fallback: create from embedded default
      console.error("Default policy not found. Create .guardian/policy.json manually.");
      process.exit(1);
    }
  }

  // Add audit log to .gitignore
  const gitignorePath = path.join(cwd, ".gitignore");
  const auditIgnore = ".guardian/audit*.jsonl\n.guardian/costs.json";
  if (fs.existsSync(gitignorePath)) {
    const existing = fs.readFileSync(gitignorePath, "utf-8");
    if (!existing.includes(".guardian/audit")) {
      fs.appendFileSync(gitignorePath, "\n" + auditIgnore + "\n");
      console.log("Added audit log patterns to .gitignore.");
    }
  }

  // Print hook setup instructions
  console.log(`
To enable Guardian as a Claude Code hook, add to .claude/settings.local.json:

{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "npx @rezzed.ai/guardian validate",
            "timeout": 5
          }
        ]
      }
    ]
  }
}
`);

  console.log("Guardian initialized.");
}

function cmdCheck(): void {
  const cwd = process.cwd();
  try {
    const policy = loadPolicy(cwd);
    console.log(`Policy valid. Mode: ${policy.mode}`);
    console.log(`  Blocklist: ${policy.blocklist.commands.length} command patterns, ${policy.blocklist.file_patterns.length} file patterns, ${policy.blocklist.secret_patterns.length} secret patterns, ${policy.blocklist.network.length} network patterns`);
    console.log(`  Scope: ${policy.scope.allowed_paths.length} allowed paths, ${policy.scope.denied_paths.length} denied paths`);
    console.log(`  Budget: ${policy.budget.enabled ? "enabled" : "disabled"}`);
    console.log(`  Audit: ${policy.audit.enabled ? "enabled" : "disabled"}`);
    console.log(`  Kill switch: ${policy.kill_switch.enabled ? "enabled" : "disabled"}`);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`Policy error: ${message}`);
    process.exit(1);
  }
}

function cmdAuditVerify(): void {
  const cwd = process.cwd();
  try {
    const policy = loadPolicy(cwd);
    const auditPath = path.resolve(cwd, policy.audit.path);
    const result = verifyAuditChain(auditPath);

    if (result.valid) {
      console.log(`✓ ${result.entries} entries verified. Chain intact.`);
    } else {
      console.error(`✗ Chain broken at entry #${result.brokenAt}. Entries after this point are untrustworthy.`);
      process.exit(1);
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`Error: ${message}`);
    process.exit(1);
  }
}

function cmdAuditSummary(): void {
  const cwd = process.cwd();
  try {
    const policy = loadPolicy(cwd);
    const auditPath = path.resolve(cwd, policy.audit.path);
    const summary = getAuditSummary(auditPath);

    console.log(`Audit Summary (${auditPath}):`);
    console.log(`  Total: ${summary.total} actions`);
    console.log(`  Allowed: ${summary.allowed}`);
    console.log(`  Denied: ${summary.denied}`);

    if (Object.keys(summary.byTool).length > 0) {
      console.log("  By tool:");
      for (const [tool, count] of Object.entries(summary.byTool).sort((a, b) => b[1] - a[1])) {
        console.log(`    ${tool}: ${count}`);
      }
    }

    if (Object.keys(summary.bySeverity).length > 0) {
      console.log("  By severity:");
      for (const [sev, count] of Object.entries(summary.bySeverity)) {
        console.log(`    ${sev}: ${count}`);
      }
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`Error: ${message}`);
    process.exit(1);
  }
}

function cmdTest(command: string): void {
  const cwd = process.cwd();
  try {
    const policy = loadPolicy(cwd);
    const input: HookInput = {
      tool_name: "Bash",
      tool_input: { command },
      cwd,
    };

    const result = validate(input, policy, cwd);

    if (result.allowed) {
      console.log(`ALLOWED: Command passed all checks.`);
    } else {
      console.log(`DENIED: ${result.reason} (severity: ${result.severity})`);
      if (result.pattern) {
        console.log(`  Pattern: ${result.pattern}`);
      }
      if (result.source) {
        console.log(`  Source: ${result.source}`);
      }
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`Error: ${message}`);
    process.exit(1);
  }
}

function cmdBudget(): void {
  const cwd = process.cwd();
  try {
    const policy = loadPolicy(cwd);
    if (!policy.budget.enabled) {
      console.log("Budget enforcement is disabled.");
      return;
    }

    console.log(`Budget configuration:`);
    console.log(`  Max actions/session: ${policy.budget.max_actions_per_session}`);
    console.log(`  Session limit: ${policy.budget.session_limit_usd !== null ? `$${policy.budget.session_limit_usd.toFixed(2)}` : "none"}`);
    console.log(`  Action on breach: ${policy.budget.action_on_breach}`);

    // Check cost file
    if (policy.budget.cost_file) {
      const costPath = path.resolve(cwd, policy.budget.cost_file);
      if (fs.existsSync(costPath)) {
        try {
          const cost = JSON.parse(fs.readFileSync(costPath, "utf-8"));
          console.log(`  Current cost: $${cost.total_cost_usd?.toFixed(2) ?? "unknown"}`);
          console.log(`  Last updated: ${cost.last_updated ?? "unknown"}`);
        } catch {
          console.log("  Cost file: unreadable");
        }
      } else {
        console.log("  Cost file: not found");
      }
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`Error: ${message}`);
    process.exit(1);
  }
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  if (args.length === 0 || args.includes("--help") || args.includes("-h")) {
    printUsage();
    process.exit(0);
  }

  const command = args[0];

  switch (command) {
    case "init":
      cmdInit();
      break;
    case "validate":
      await handleHook();
      break;
    case "check":
      cmdCheck();
      break;
    case "audit":
      if (args[1] === "verify") cmdAuditVerify();
      else if (args[1] === "summary") cmdAuditSummary();
      else { console.error("Usage: guardian audit verify|summary"); process.exit(1); }
      break;
    case "test":
      if (!args[1]) { console.error("Usage: guardian test \"<command>\""); process.exit(1); }
      cmdTest(args[1]);
      break;
    case "budget":
      cmdBudget();
      break;
    default:
      console.error(`Unknown command: ${command}`);
      printUsage();
      process.exit(1);
  }
}

main();
