import type { CommandPattern } from "../types";

export const DESTRUCTIVE_PATTERNS: CommandPattern[] = [
  {
    pattern: "rm\\s+(-[a-zA-Z]*f[a-zA-Z]*|--force)",
    severity: "critical",
    reason: "Forced file deletion",
  },
  {
    pattern: "rm\\s+(-[a-zA-Z]*r[a-zA-Z]*|--recursive)\\s+/(?!tmp)",
    severity: "critical",
    reason: "Recursive deletion outside /tmp",
  },
  {
    pattern: "git\\s+push\\s+.*--force",
    severity: "high",
    reason: "Force push can destroy remote history",
  },
  {
    pattern: "git\\s+reset\\s+--hard",
    severity: "high",
    reason: "Hard reset destroys uncommitted work",
  },
  {
    pattern: "git\\s+clean\\s+.*-f",
    severity: "high",
    reason: "Git clean -f deletes untracked files permanently",
  },
  {
    pattern: "DROP\\s+(TABLE|DATABASE|INDEX)",
    severity: "critical",
    reason: "SQL destructive operation",
    flags: "i",
  },
  {
    pattern: "TRUNCATE\\s+TABLE",
    severity: "critical",
    reason: "SQL destructive operation",
    flags: "i",
  },
  {
    pattern: "\\bmkfs\\b",
    severity: "critical",
    reason: "Disk formatting",
  },
  {
    pattern: "\\bdd\\s+if=",
    severity: "critical",
    reason: "Raw disk write",
  },
  {
    pattern: "kill\\s+-9",
    severity: "high",
    reason: "Force kill process",
  },
  {
    pattern: "pkill\\s+-9",
    severity: "high",
    reason: "Force kill processes by name",
  },
];
