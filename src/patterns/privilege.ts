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
  {
    pattern: "\\bsu\\s+-",
    severity: "high",
    reason: "Switch user to root",
  },
  {
    pattern: "\\bsu\\s+root",
    severity: "high",
    reason: "Switch user to root",
  },
  {
    pattern: "setuid|setgid",
    severity: "high",
    reason: "Set user/group ID on execution",
  },
  {
    pattern: "\\bmount\\s+",
    severity: "high",
    reason: "Mount filesystem — requires elevated privileges",
  },
  {
    pattern: "\\bumount\\s+",
    severity: "high",
    reason: "Unmount filesystem — requires elevated privileges",
  },
  {
    pattern: "crontab\\s+-e",
    severity: "high",
    reason: "Edit crontab — persistent execution",
  },
  {
    pattern: "\\bvisudo\\b",
    severity: "critical",
    reason: "Edit sudoers file",
  },
  {
    pattern: "/etc/sudoers",
    severity: "critical",
    reason: "Access to sudoers file",
  },
];
