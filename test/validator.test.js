import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

import { validate, validateAndAudit } from "../dist/validator.js";
import { resetActionCount } from "../dist/budget.js";
import { resetAuditState } from "../dist/audit.js";
import { resetCompiledPatterns } from "../dist/blocklist.js";

const policy = JSON.parse(
  fs.readFileSync(path.join(__dirname, "../.guardian/policy.default.json"), "utf8")
);

describe("validator", () => {
  let tempDir;

  beforeEach(() => {
    resetActionCount();
    resetAuditState();
    resetCompiledPatterns();
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "guardian-validator-"));
  });

  afterEach(() => {
    if (tempDir && fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  describe("mode: off", () => {
    it("should allow everything when mode is off", () => {
      const testPolicy = {
        ...policy,
        mode: "off",
      };

      const input = {
        tool_name: "Bash",
        tool_input: { command: "rm -rf /" },
      };

      const result = validate(input, testPolicy, tempDir);
      assert.equal(result.allowed, true);
    });
  });

  describe("mode: enforce", () => {
    it("should allow safe commands", () => {
      const testPolicy = {
        ...policy,
        mode: "enforce",
      };

      const input = {
        tool_name: "Bash",
        tool_input: { command: "ls -la" },
      };

      const result = validate(input, testPolicy, tempDir);
      assert.equal(result.allowed, true);
    });

    it("should block dangerous commands", () => {
      const testPolicy = {
        ...policy,
        mode: "enforce",
      };

      const input = {
        tool_name: "Bash",
        tool_input: { command: "rm -rf /" },
      };

      const result = validate(input, testPolicy, tempDir);
      assert.equal(result.allowed, false);
      assert.equal(result.source, "blocklist");
    });

    it("should enforce scope restrictions", () => {
      const testPolicy = {
        ...policy,
        mode: "enforce",
        scope: {
          allowed_paths: ["{cwd}"],
          denied_paths: ["/etc"],
          allow_outside_cwd: false,
        },
      };

      const input = {
        tool_name: "Read",
        tool_input: { file_path: "/etc/passwd" },
      };

      const result = validate(input, testPolicy, tempDir);
      assert.equal(result.allowed, false);
      assert.equal(result.source, "scope");
    });
  });

  describe("mode: audit", () => {
    it("should allow violations but record them", () => {
      const testPolicy = {
        ...policy,
        mode: "audit",
      };

      const input = {
        tool_name: "Bash",
        tool_input: { command: "rm -rf /" },
      };

      const result = validate(input, testPolicy, tempDir);
      assert.equal(result.allowed, true);
      assert.equal(result.severity, "critical");
      assert.equal(result.source, "blocklist");
    });
  });

  describe("allowlist", () => {
    it("should skip blocklist check for allowlisted command", () => {
      const testPolicy = {
        ...policy,
        allowlist: {
          commands: ["rm -rf /tmp/test"],
          paths: [],
          domains: [],
        },
      };

      const input = {
        tool_name: "Bash",
        tool_input: { command: "rm -rf /tmp/test" },
      };

      const result = validate(input, testPolicy, tempDir);
      assert.equal(result.allowed, true);
      assert.equal(result.source, "allowlist");
    });

    it("should skip blocklist check for allowlisted path", () => {
      const testPolicy = {
        ...policy,
        allowlist: {
          commands: [],
          paths: ["/tmp"],
          domains: [],
        },
      };

      const input = {
        tool_name: "Write",
        tool_input: {
          file_path: "/tmp/test.txt",
          content: "test",
        },
      };

      const result = validate(input, testPolicy, tempDir);
      assert.equal(result.allowed, true);
      assert.equal(result.source, "allowlist");
    });

    it("should skip blocklist check for allowlisted domain", () => {
      const testPolicy = {
        ...policy,
        allowlist: {
          commands: [],
          paths: [],
          domains: ["github.com"],
        },
      };

      const input = {
        tool_name: "WebFetch",
        tool_input: { url: "https://github.com/test" },
      };

      const result = validate(input, testPolicy, tempDir);
      assert.equal(result.allowed, true);
      assert.equal(result.source, "allowlist");
    });
  });

  describe("scope enforcement", () => {
    it("should allow files within cwd when allow_outside_cwd is false", () => {
      const testPolicy = {
        ...policy,
        scope: {
          allowed_paths: ["{cwd}"],
          denied_paths: [],
          allow_outside_cwd: false,
        },
      };

      const filePath = path.join(tempDir, "test.txt");
      const input = {
        tool_name: "Write",
        tool_input: { file_path: filePath, content: "test" },
      };

      const result = validate(input, testPolicy, tempDir);
      assert.equal(result.allowed, true);
    });

    it("should block files outside cwd when allow_outside_cwd is false", () => {
      const testPolicy = {
        ...policy,
        scope: {
          allowed_paths: ["{cwd}"],
          denied_paths: [],
          allow_outside_cwd: false,
        },
      };

      const input = {
        tool_name: "Write",
        tool_input: { file_path: "/tmp/outside.txt", content: "test" },
      };

      const result = validate(input, testPolicy, tempDir);
      assert.equal(result.allowed, false);
      assert.equal(result.source, "scope");
    });

    it("should block denied paths", () => {
      const testPolicy = {
        ...policy,
        scope: {
          allowed_paths: ["{cwd}"],
          denied_paths: ["/etc", "/usr"],
          allow_outside_cwd: true,
        },
      };

      const input = {
        tool_name: "Read",
        tool_input: { file_path: "/etc/hosts" },
      };

      const result = validate(input, testPolicy, tempDir);
      assert.equal(result.allowed, false);
      assert.equal(result.source, "scope");
    });
  });

  describe("budget enforcement", () => {
    it("should deny when budget is exceeded", () => {
      const testPolicy = {
        ...policy,
        budget: {
          enabled: true,
          max_actions_per_session: 2,
          session_limit_usd: null,
          cost_file: "costs.json",
          action_on_breach: "deny",
        },
      };

      const input = {
        tool_name: "Bash",
        tool_input: { command: "echo test" },
      };

      // First two should succeed
      let result = validate(input, testPolicy, tempDir);
      assert.equal(result.allowed, true);

      result = validate(input, testPolicy, tempDir);
      assert.equal(result.allowed, true);

      // Third should fail due to budget
      result = validate(input, testPolicy, tempDir);
      assert.equal(result.allowed, false);
      assert.equal(result.source, "budget");
    });
  });

  describe("validateAndAudit", () => {
    it("should write audit entry", () => {
      const testPolicy = {
        ...policy,
        audit: {
          ...policy.audit,
          enabled: true,
          path: ".guardian/audit.jsonl",
        },
      };

      const input = {
        tool_name: "Bash",
        tool_input: { command: "ls" },
        session_id: "test",
      };

      const result = validateAndAudit(input, testPolicy, tempDir);
      assert.equal(result.allowed, true);

      const auditPath = path.join(tempDir, testPolicy.audit.path);
      assert.ok(fs.existsSync(auditPath));

      const content = fs.readFileSync(auditPath, "utf-8");
      assert.ok(content.length > 0);
    });
  });

  describe("full integration", () => {
    it("should perform complete validation flow", () => {
      const testPolicy = {
        ...policy,
        mode: "enforce",
        kill_switch: {
          enabled: false,
          on_blocklist_critical: false,
          on_budget_breach: false,
          on_integrity_violation: false,
          exit_code: 2,
        },
        budget: {
          enabled: true,
          max_actions_per_session: 100,
          session_limit_usd: null,
          cost_file: "costs.json",
          action_on_breach: "deny",
        },
        audit: {
          ...policy.audit,
          enabled: true,
          path: ".guardian/audit.jsonl",
        },
      };

      // Test safe command
      let input = {
        tool_name: "Bash",
        tool_input: { command: "echo hello" },
        session_id: "test",
      };

      let result = validateAndAudit(input, testPolicy, tempDir);
      assert.equal(result.allowed, true);

      // Test dangerous command (with kill switch disabled)
      input = {
        tool_name: "Bash",
        tool_input: { command: "rm -rf /" },
        session_id: "test",
      };

      result = validateAndAudit(input, testPolicy, tempDir);
      assert.equal(result.allowed, false);
      assert.equal(result.severity, "critical");

      // Verify both entries were audited
      const auditPath = path.join(tempDir, testPolicy.audit.path);
      const content = fs.readFileSync(auditPath, "utf-8");
      const lines = content.trim().split("\n");
      assert.equal(lines.length, 2);
    });
  });
});
