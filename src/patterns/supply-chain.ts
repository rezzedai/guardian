import type { CommandPattern } from "../types";

export const SUPPLY_CHAIN_PATTERNS: CommandPattern[] = [
  {
    pattern: "npm\\s+install\\s+.*--registry\\s+(?!https://registry\\.npmjs\\.org)",
    severity: "medium",
    reason: "npm install from non-standard registry",
  },
  {
    pattern: "pip\\s+install\\s+https?://",
    severity: "medium",
    reason: "pip install from URL — untrusted package source",
  },
];
