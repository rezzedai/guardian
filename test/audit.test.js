import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

import {
  writeAuditEntry,
  verifyAuditChain,
  getAuditSummary,
  resetAuditState,
} from "../dist/audit.js";

const policy = JSON.parse(
  fs.readFileSync(path.join(__dirname, "../.guardian/policy.default.json"), "utf8")
);

describe("audit", () => {
  let tempDir;
  let testPolicy;

  beforeEach(() => {
    resetAuditState();
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-test-"));
    testPolicy = {
      ...policy,
      audit: {
        ...policy.audit,
        path: ".guardian/audit.jsonl",
      },
    };
  });

  afterEach(() => {
    if (tempDir && fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("should write audit entry to file", () => {
    const input = {
      tool_name: "Bash",
      tool_input: { command: "ls -la" },
      session_id: "test-session",
    };

    const result = {
      allowed: true,
      reason: null,
      severity: null,
      pattern: null,
      source: null,
    };

    writeAuditEntry(input, result, testPolicy, tempDir, {
      remaining_usd: null,
      action_count: 1,
    });

    const auditPath = path.join(tempDir, testPolicy.audit.path);
    assert.ok(fs.existsSync(auditPath));

    const content = fs.readFileSync(auditPath, "utf-8");
    const lines = content.trim().split("\n");
    assert.equal(lines.length, 1);

    const entry = JSON.parse(lines[0]);
    assert.equal(entry.v, 1);
    assert.equal(entry.sid, "test-session");
    assert.equal(entry.seq, 1);
    assert.equal(entry.tool, "Bash");
    assert.equal(entry.allowed, true);
    assert.ok(entry.hash.startsWith("sha256:"));
  });

  it("should create valid hash chain for multiple entries", () => {
    const input1 = {
      tool_name: "Bash",
      tool_input: { command: "ls" },
      session_id: "test",
    };
    const input2 = {
      tool_name: "Read",
      tool_input: { file_path: "/tmp/test.txt" },
      session_id: "test",
    };

    const result = {
      allowed: true,
      reason: null,
      severity: null,
      pattern: null,
      source: null,
    };

    writeAuditEntry(input1, result, testPolicy, tempDir, {
      remaining_usd: null,
      action_count: 1,
    });
    writeAuditEntry(input2, result, testPolicy, tempDir, {
      remaining_usd: null,
      action_count: 2,
    });

    const auditPath = path.join(tempDir, testPolicy.audit.path);
    const content = fs.readFileSync(auditPath, "utf-8");
    const lines = content.trim().split("\n");

    const entry1 = JSON.parse(lines[0]);
    const entry2 = JSON.parse(lines[1]);

    assert.equal(entry1.seq, 1);
    assert.equal(entry2.seq, 2);

    // Hash chain verification: entry2's hash should incorporate entry1's hash
    assert.ok(entry1.hash.startsWith("sha256:"));
    assert.ok(entry2.hash.startsWith("sha256:"));
    assert.notEqual(entry1.hash, entry2.hash);
  });

  it("should verify valid audit chain", () => {
    const input = {
      tool_name: "Bash",
      tool_input: { command: "echo test" },
      session_id: "test",
    };

    const result = {
      allowed: true,
      reason: null,
      severity: null,
      pattern: null,
      source: null,
    };

    writeAuditEntry(input, result, testPolicy, tempDir, {
      remaining_usd: null,
      action_count: 1,
    });
    writeAuditEntry(input, result, testPolicy, tempDir, {
      remaining_usd: null,
      action_count: 2,
    });
    writeAuditEntry(input, result, testPolicy, tempDir, {
      remaining_usd: null,
      action_count: 3,
    });

    const auditPath = path.join(tempDir, testPolicy.audit.path);
    const verification = verifyAuditChain(auditPath);

    assert.equal(verification.valid, true);
    assert.equal(verification.entries, 3);
    assert.equal(verification.brokenAt, null);
  });

  it("should detect tampered audit chain", () => {
    const input = {
      tool_name: "Bash",
      tool_input: { command: "echo test" },
      session_id: "test",
    };

    const result = {
      allowed: true,
      reason: null,
      severity: null,
      pattern: null,
      source: null,
    };

    writeAuditEntry(input, result, testPolicy, tempDir, {
      remaining_usd: null,
      action_count: 1,
    });
    writeAuditEntry(input, result, testPolicy, tempDir, {
      remaining_usd: null,
      action_count: 2,
    });

    const auditPath = path.join(tempDir, testPolicy.audit.path);

    // Tamper with the second entry
    const content = fs.readFileSync(auditPath, "utf-8");
    const lines = content.trim().split("\n");
    const entry2 = JSON.parse(lines[1]);
    entry2.tool = "TAMPERED"; // Change the tool name
    lines[1] = JSON.stringify(entry2);

    fs.writeFileSync(auditPath, lines.join("\n") + "\n");

    const verification = verifyAuditChain(auditPath);
    assert.equal(verification.valid, false);
    assert.equal(verification.brokenAt, 2);
  });

  it("should return correct audit summary", () => {
    const allowedInput = {
      tool_name: "Bash",
      tool_input: { command: "ls" },
      session_id: "test",
    };

    const deniedInput = {
      tool_name: "Bash",
      tool_input: { command: "rm -rf /" },
      session_id: "test",
    };

    const allowedResult = {
      allowed: true,
      reason: null,
      severity: null,
      pattern: null,
      source: null,
    };

    const deniedResult = {
      allowed: false,
      reason: "Destructive command",
      severity: "critical",
      pattern: "rm.*-rf",
      source: "blocklist",
    };

    writeAuditEntry(allowedInput, allowedResult, testPolicy, tempDir, {
      remaining_usd: null,
      action_count: 1,
    });
    writeAuditEntry(deniedInput, deniedResult, testPolicy, tempDir, {
      remaining_usd: null,
      action_count: 2,
    });
    writeAuditEntry(allowedInput, allowedResult, testPolicy, tempDir, {
      remaining_usd: null,
      action_count: 3,
    });

    const auditPath = path.join(tempDir, testPolicy.audit.path);
    const summary = getAuditSummary(auditPath);

    assert.equal(summary.total, 3);
    assert.equal(summary.allowed, 2);
    assert.equal(summary.denied, 1);
    assert.equal(summary.byTool["Bash"], 3);
    assert.equal(summary.bySeverity["critical"], 1);
  });

  it("should reset audit state", () => {
    const input = {
      tool_name: "Bash",
      tool_input: { command: "echo test" },
      session_id: "test",
    };

    const result = {
      allowed: true,
      reason: null,
      severity: null,
      pattern: null,
      source: null,
    };

    writeAuditEntry(input, result, testPolicy, tempDir, {
      remaining_usd: null,
      action_count: 1,
    });

    resetAuditState();

    // After reset, a new entry should start sequence from 1 again
    const tempDir2 = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-test-2-"));
    const testPolicy2 = {
      ...policy,
      audit: {
        ...policy.audit,
        path: ".guardian/audit-2.jsonl",
      },
    };

    writeAuditEntry(input, result, testPolicy2, tempDir2, {
      remaining_usd: null,
      action_count: 1,
    });

    const auditPath2 = path.join(tempDir2, testPolicy2.audit.path);
    const content = fs.readFileSync(auditPath2, "utf-8");
    const entry = JSON.parse(content.trim());

    assert.equal(entry.seq, 1);

    // Cleanup
    fs.rmSync(tempDir2, { recursive: true, force: true });
  });

  it("should return empty summary for non-existent audit file", () => {
    const auditPath = path.join(tempDir, "non-existent.jsonl");
    const summary = getAuditSummary(auditPath);

    assert.equal(summary.total, 0);
    assert.equal(summary.allowed, 0);
    assert.equal(summary.denied, 0);
  });

  it("should verify empty audit file as valid", () => {
    const auditPath = path.join(tempDir, "empty.jsonl");
    const verification = verifyAuditChain(auditPath);

    assert.equal(verification.valid, true);
    assert.equal(verification.entries, 0);
    assert.equal(verification.brokenAt, null);
  });
});
