import type { CommandPattern } from "../types";

export const PRIVILEGE_PATTERNS: CommandPattern[] = [
  {
    pattern: "\\bsudo\\b",
    severity: "high",
    reason: "Privilege escalation via sudo",
  },
  {
    pattern: "chmod\\s+777",
    severity: "high",
    reason: "World-writable permissions",
  },
  {
    pattern: "\\bchown\\s+root\\b",
    severity: "high",
    reason: "Ownership change to root",
  },
  {
    pattern: "chmod\\s+[ug]\\+s",
    severity: "high",
    reason: "Setuid/setgid bit — privilege inheritance on execution",
  },
];
