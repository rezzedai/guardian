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
  {
    pattern: "wget\\s+https?://(?!localhost|127\\.0\\.0\\.1)",
    severity: "medium",
    reason: "Download from external host",
  },
  {
    pattern: "\\bnc\\s+-[a-zA-Z]*l",
    severity: "critical",
    reason: "Netcat listen mode — potential reverse shell",
  },
  {
    pattern: "\\bnetcat\\s+-[a-zA-Z]*l",
    severity: "critical",
    reason: "Netcat listen mode — potential reverse shell",
  },
  {
    pattern: "ssh\\s+.*-[a-zA-Z]*R",
    severity: "high",
    reason: "SSH reverse tunnel",
  },
  {
    pattern: "ssh\\s+.*-[a-zA-Z]*L",
    severity: "medium",
    reason: "SSH local port forwarding",
  },
  {
    pattern: "base64.*\\|\\s*curl",
    severity: "high",
    reason: "Base64 encode and exfiltrate via curl",
  },
  {
    pattern: "dig\\s+.*@(?!8\\.8\\.8\\.8|1\\.1\\.1\\.1)",
    severity: "medium",
    reason: "DNS query to non-standard server — potential DNS exfiltration",
  },
  {
    pattern: "nslookup.*\\$",
    severity: "medium",
    reason: "DNS query with variable expansion — potential DNS exfiltration",
  },
  {
    pattern: "rsync\\s+.*@[^:]+:",
    severity: "medium",
    reason: "Rsync to remote host",
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
