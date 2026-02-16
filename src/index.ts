export { validate, validateAndAudit } from "./validator";
export { loadPolicy, getDefaultPolicyPath } from "./policy";
export { verifyAuditChain, getAuditSummary } from "./audit";
export { handleHook } from "./hook";

export type {
  Policy,
  BlocklistConfig,
  CommandPattern,
  FilePattern,
  SecretPattern,
  NetworkPattern,
  AllowlistConfig,
  ScopeConfig,
  BudgetConfig,
  AuditConfig,
  KillSwitchConfig,
  Severity,
  FileOperation,
  HookInput,
  HookOutput,
  ValidationResult,
  AuditEntry,
  CostFile,
  BudgetState,
} from "./types";
