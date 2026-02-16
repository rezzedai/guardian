import type { CommandPattern, NetworkPattern } from "../types";

export const EXFILTRATION_COMMAND_PATTERNS: CommandPattern[] = [
  {
    pattern: "curl\\s.*\\|\\s*(ba)?sh",
    severity: "critical",
    reason: "Remote code execution via pipe to shell",
  },
  {
    pattern: "\\beval\\b.*\\$",
    severity: "high",
    reason: "Dynamic eval with variable expansion",
  },
];

export const NETWORK_PATTERNS: NetworkPattern[] = [
  {
    pattern: "169\\.254\\.169\\.254",
    severity: "critical",
    reason: "AWS metadata endpoint — SSRF vector",
  },
  {
    pattern: "metadata\\.google\\.internal",
    severity: "critical",
    reason: "GCP metadata endpoint — SSRF vector",
  },
];
