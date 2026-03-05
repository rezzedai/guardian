import type { CommandPattern } from "../types";

export const GIT_PATTERNS: CommandPattern[] = [
  {
    pattern: "git\\s+push\\s+.*--force",
    severity: "high",
    reason: "Force push can destroy remote history",
  },
  {
    pattern: "git\\s+push\\s+.*-f\\s",
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
    pattern: "git\\s+checkout\\s+\\.",
    severity: "high",
    reason: "Discard all working directory changes",
  },
  {
    pattern: "git\\s+checkout\\s+--\\s+\\.",
    severity: "high",
    reason: "Discard all working directory changes",
  },
  {
    pattern: "git\\s+rebase\\s+.*(?:main|master|develop)",
    severity: "medium",
    reason: "Rebase on shared branch — can rewrite history",
  },
  {
    pattern: "git\\s+push\\s+origin\\s+:",
    severity: "high",
    reason: "Delete remote branch",
  },
  {
    pattern: "git\\s+filter-branch",
    severity: "critical",
    reason: "History rewriting — destructive operation",
  },
  {
    pattern: "git\\s+branch\\s+-D",
    severity: "high",
    reason: "Force delete git branch",
  },
];
