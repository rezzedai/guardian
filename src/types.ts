// --- Policy Schema ---

export interface Policy {
  version: number;
  mode: "enforce" | "audit" | "off";
  blocklist: BlocklistConfig;
  allowlist: AllowlistConfig;
  scope: ScopeConfig;
  budget: BudgetConfig;
  audit: AuditConfig;
  kill_switch: KillSwitchConfig;
}

export interface BlocklistConfig {
  commands: CommandPattern[];
  file_patterns: FilePattern[];
  secret_patterns: SecretPattern[];
  network: NetworkPattern[];
}

export interface CommandPattern {
  pattern: string;
  severity: Severity;
  reason: string;
  flags?: string;
}

export interface FilePattern {
  pattern: string;
  operations: FileOperation[];
  severity: Severity;
  reason: string;
}

export interface SecretPattern {
  pattern: string;
  severity: Severity;
  reason: string;
  flags?: string;
}

export interface NetworkPattern {
  pattern: string;
  severity: Severity;
  reason: string;
}

export interface AllowlistConfig {
  commands: string[];
  paths: string[];
  domains: string[];
}

export interface ScopeConfig {
  allowed_paths: string[];
  denied_paths: string[];
  allow_outside_cwd: boolean;
}

export interface BudgetConfig {
  enabled: boolean;
  max_actions_per_session: number;
  session_limit_usd: number | null;
  cost_file: string;
  action_on_breach: "kill" | "deny" | "warn";
}

export interface AuditConfig {
  enabled: boolean;
  path: string;
  include_tool_input: boolean;
  include_tool_output: boolean;
  integrity: "sha256-chain" | "none";
  max_file_size_mb: number;
  rotation: "daily" | "none";
}

export interface KillSwitchConfig {
  enabled: boolean;
  on_blocklist_critical: boolean;
  on_budget_breach: boolean;
  on_integrity_violation: boolean;
  exit_code: number;
}

export type Severity = "critical" | "high" | "medium" | "low";
export type FileOperation = "read" | "write" | "delete" | "git_add";

// --- Hook Input/Output ---

export interface HookInput {
  tool_name: string;
  tool_input: Record<string, unknown>;
  session_id?: string;
  cwd?: string;
}

export interface HookOutput {
  permissionDecision: "allow" | "deny";
  reason?: string;
  systemMessage?: string;
}

// --- Validation ---

export interface ValidationResult {
  allowed: boolean;
  reason: string | null;
  severity: Severity | null;
  pattern: string | null;
  source: "allowlist" | "scope" | "blocklist" | "budget" | null;
}

// --- Audit ---

export interface AuditEntry {
  v: number;
  ts: string;
  sid: string;
  seq: number;
  tool: string;
  input: Record<string, unknown> | null;
  allowed: boolean;
  reason: string | null;
  severity: Severity | null;
  policy_match: string | null;
  budget: { remaining_usd: number | null; action_count: number } | null;
  cwd: string;
  hash: string;
}

// --- Budget ---

export interface CostFile {
  session_id: string;
  total_cost_usd: number;
  last_updated: string;
}

export interface BudgetState {
  action_count: number;
  session_cost_usd: number | null;
  exceeded: boolean;
  breach_reason: string | null;
}
