import type { SecretPattern, FilePattern } from "../types";

export const SECRET_CONTENT_PATTERNS: SecretPattern[] = [
  {
    pattern: "(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token)\\s*[:=]\\s*['\"]?[A-Za-z0-9+/=_-]{20,}",
    severity: "high",
    reason: "Potential API key or secret in content",
    flags: "i",
  },
  {
    pattern: "-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    severity: "critical",
    reason: "Private key in content",
  },
  {
    pattern: "AKIA[0-9A-Z]{16}",
    severity: "critical",
    reason: "AWS access key ID",
  },
  {
    pattern: "sk-[a-zA-Z0-9]{20,}",
    severity: "high",
    reason: "Potential API secret key (OpenAI, Stripe, etc.)",
  },
];

export const SECRET_FILE_PATTERNS: FilePattern[] = [
  {
    pattern: "\\.env$",
    operations: ["write", "delete", "git_add"],
    severity: "high",
    reason: "Environment file with potential secrets",
  },
  {
    pattern: "credentials\\.json$",
    operations: ["write", "delete", "git_add"],
    severity: "critical",
    reason: "Credentials file",
  },
  {
    pattern: "id_rsa$|id_ed25519$|\\.pem$",
    operations: ["read", "write", "delete", "git_add"],
    severity: "critical",
    reason: "Private key file",
  },
];
