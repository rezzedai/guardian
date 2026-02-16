# @rezzedai/guardian

**Safety rails, audit trail, and budget enforcement for AI agent sessions.**

```json
{
  "hooks": {
    "PreToolUse": [{
      "matcher": "",
      "hooks": [{
        "type": "command",
        "command": "npx @rezzedai/guardian validate",
        "timeout": 5
      }]
    }]
  }
}
```

---

## What It Does

- **Blocks destructive commands** — `rm -rf`, `DROP TABLE`, `git push --force`, disk formatting, privilege escalation
- **Prevents secret leaks** — detects API keys, AWS credentials, private keys in files and git commits
- **Enforces scope boundaries** — restricts file operations to project directory, blocks system paths
- **Audits every tool call** — tamper-proof JSONL log with SHA256-chain integrity
- **Enforces budgets** — action count limits and cost caps with configurable breach actions
- **Validates network access** — blocks SSRF vectors (AWS/GCP metadata endpoints)
- **Works with all Claude Code tools** — Bash, Read/Write/Edit, WebFetch, and custom MCP tools

---

## Install

```bash
npm install @rezzedai/guardian
```

**Requirements:** Node.js 18+

**Zero runtime dependencies.**

---

## Quick Start

### 1. Initialize in your project

```bash
npx guardian init
```

Creates `.guardian/policy.json` with sensible defaults and updates `.gitignore`.

### 2. Add hook to Claude Code settings

Edit `.claude/settings.local.json`:

```json
{
  "hooks": {
    "PreToolUse": [{
      "matcher": "",
      "hooks": [{
        "type": "command",
        "command": "npx @rezzedai/guardian validate",
        "timeout": 5
      }]
    }]
  }
}
```

### 3. Start Claude Code

Every tool call now passes through guardian before execution.

---

## How It Works

```
Claude Code Tool Call
        ↓
guardian validate (stdin)
        ↓
┌───────────────────────┐
│ 1. Policy mode check  │ → off? bypass all checks
├───────────────────────┤
│ 2. Allowlist check    │ → matched? allow immediately
├───────────────────────┤
│ 3. Scope check        │ → file paths in allowed dirs?
├───────────────────────┤
│ 4. Blocklist check    │ → command/file/secret/network patterns
├───────────────────────┤
│ 5. Budget check       │ → action count + cost limits
├───────────────────────┤
│ 6. Kill switch        │ → critical violations terminate session
└───────────────────────┘
        ↓
Allow / Deny (stdout)
        ↓
Audit log (.guardian/audit.jsonl)
```

---

## CLI Reference

| Command | Description |
|---------|-------------|
| `guardian init` | Initialize in project — creates `.guardian/policy.json`, updates `.gitignore` |
| `guardian validate` | Hook mode — reads HookInput from stdin, outputs allow/deny decision |
| `guardian check` | Validate policy file syntax, show loaded rules summary |
| `guardian audit verify` | Verify audit trail integrity (SHA256-chain) |
| `guardian audit summary` | Print audit event summary (allowed/denied breakdown) |
| `guardian test "<cmd>"` | Dry-run a command against policy without executing |
| `guardian budget` | Show budget config and current spend |

---

## Policy Configuration

`.guardian/policy.json` controls all validation behavior.

```jsonc
{
  "version": 1,
  "mode": "enforce",  // enforce | audit | off

  "blocklist": {
    "commands": [
      // Regex patterns for dangerous commands
      { "pattern": "rm\\s+(-[a-zA-Z]*f[a-zA-Z]*|--force)", "severity": "critical", "reason": "Forced deletion" }
    ],
    "file_patterns": [
      // File path patterns with operation constraints
      { "pattern": "\\.env$", "operations": ["write", "git_add"], "severity": "high", "reason": "Environment file" }
    ],
    "secret_patterns": [
      // Content patterns for secrets
      { "pattern": "AKIA[0-9A-Z]{16}", "severity": "critical", "reason": "AWS access key" }
    ],
    "network": [
      // URL patterns to block
      { "pattern": "169\\.254\\.169\\.254", "severity": "critical", "reason": "AWS metadata endpoint" }
    ]
  },

  "allowlist": {
    "commands": [],    // Exact command strings that bypass blocklist
    "paths": [],       // File paths that bypass blocklist
    "domains": []      // Domains that bypass network blocklist
  },

  "scope": {
    "allowed_paths": ["{cwd}"],  // {cwd} expands to working directory
    "denied_paths": ["/etc", "/usr", "/var", "/sys"],
    "allow_outside_cwd": false
  },

  "budget": {
    "enabled": false,
    "max_actions_per_session": 500,  // Tool call count limit
    "session_limit_usd": null,        // Cost limit (reads from cost_file)
    "cost_file": ".guardian/costs.json",
    "action_on_breach": "kill"        // kill | deny | warn
  },

  "audit": {
    "enabled": true,
    "path": ".guardian/audit.jsonl",
    "include_tool_input": true,
    "include_tool_output": false,
    "integrity": "sha256-chain",      // Each entry hashes previous entry
    "max_file_size_mb": 50,
    "rotation": "daily"               // daily | weekly | size
  },

  "kill_switch": {
    "enabled": true,
    "on_blocklist_critical": true,   // Terminate on critical violations
    "on_budget_breach": true,         // Terminate on budget breach
    "on_integrity_violation": true,   // Terminate on audit tampering
    "exit_code": 2
  }
}
```

**Policy modes:**

| Mode | Behavior |
|------|----------|
| `enforce` | Violations block execution |
| `audit` | Violations logged but allowed |
| `off` | All checks disabled |

---

## Built-in Patterns

guardian ships with 50+ dangerous patterns across 5 categories.

### Destructive Commands (severity: critical/high)

- `rm -f`, `rm -r /` — forced/recursive deletion
- `git push --force`, `git reset --hard`, `git clean -f` — git data loss
- `DROP TABLE`, `DROP DATABASE`, `TRUNCATE TABLE` — SQL destructive operations
- `mkfs`, `dd if=` — disk formatting and raw writes
- `kill -9`, `pkill -9` — force kill processes

### Privilege Escalation (severity: high)

- `sudo` — privilege escalation
- `chmod 777` — world-writable permissions
- `chown root` — ownership change to root

### Secrets (severity: critical/high)

**File patterns:**
- `.env` — environment files
- `credentials.json` — credential files
- `id_rsa`, `id_ed25519`, `.pem` — SSH/TLS private keys

**Content patterns:**
- `api_key=`, `secret_key=`, `access_token=` — API credentials
- `-----BEGIN PRIVATE KEY-----` — PEM-encoded private keys
- `AKIA...` — AWS access key IDs
- `sk-...` — API secret keys (OpenAI, Stripe, etc.)

### Exfiltration (severity: critical)

- `curl | sh`, `eval $...` — remote code execution
- `169.254.169.254` — AWS metadata endpoint (SSRF)
- `metadata.google.internal` — GCP metadata endpoint (SSRF)

### Supply Chain (severity: high)

- `npm install --registry <non-npm>` — untrusted registry
- `pip install https://...` — pip from URL

---

## Audit Trail

guardian writes a tamper-proof audit log for every tool call.

**Format:** JSONL (one JSON object per line)

```json
{
  "timestamp": "2026-02-15T22:45:12.345Z",
  "tool": "Bash",
  "input": { "command": "rm file.txt" },
  "allowed": false,
  "reason": "Blocklist violation: rm -f (Forced deletion)",
  "severity": "critical",
  "budget": { "actions": 42, "cost_usd": 1.23 },
  "hash": "abc123..."
}
```

**Integrity:** Each entry includes a SHA256 hash of `previous_hash + current_entry`. Tampering breaks the chain.

**Verify integrity:**

```bash
guardian audit verify
```

**View summary:**

```bash
guardian audit summary
```

**Rotation:** Logs rotate by size (default 50MB) or daily. Old logs preserved with `.1`, `.2` suffixes.

---

## Safety Rails

| Check | Blocks | Severity |
|-------|--------|----------|
| **Destructive commands** | `rm -rf`, `DROP TABLE`, `git push --force`, disk formatting | Critical/High |
| **Privilege escalation** | `sudo`, `chmod 777`, `chown root` | High |
| **Secret leaks** | API keys, AWS credentials, private keys in files/git | Critical/High |
| **Exfiltration** | Remote code execution, SSRF vectors | Critical |
| **Scope violations** | File operations outside project directory | Medium |
| **Budget breach** | Action count or cost limits exceeded | Configurable |

---

## Technical Details

| | |
|---|---|
| **Runtime** | Node.js 18+ |
| **Dependencies** | Zero runtime dependencies |
| **Transport** | stdin/stdout (Claude Code hook protocol) |
| **Validation** | Bash command parsing (handles `&&`, `\|\|`, `;`, `\|` splitting) |
| **Supported tools** | Bash, Read/Write/Edit, WebFetch, all MCP tools |
| **Language** | TypeScript with declarations |
| **License** | MIT |

---

## Why Not...?

**Why not just use Claude Code's built-in permission prompts?**

- No audit trail
- No pattern library (you define every dangerous command manually)
- No budget enforcement
- No integrity verification
- No cross-session policy management

**Why not write your own hooks?**

guardian ships with 50+ dangerous patterns built in — covering destructive commands, secret leaks, privilege escalation, exfiltration, and supply chain attacks. Building this yourself takes weeks. guardian takes 2 minutes.

---

## What's Next?

More tools coming from the @rezzedai toolkit. See [rezzed.ai](https://rezzed.ai) for updates.

---

## License

MIT

---

Built by [Rezzed](https://rezzed.ai) — the AI product studio.
