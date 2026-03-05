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
  {
    pattern: "aws_secret_access_key\\s*[:=]\\s*['\"]?[A-Za-z0-9+/]{40}",
    severity: "critical",
    reason: "AWS secret access key",
    flags: "i",
  },
  {
    pattern: "private_key.*:.*-----BEGIN",
    severity: "critical",
    reason: "GCP service account private key in JSON",
  },
  {
    pattern: "postgres://[^:]+:[^@]+@",
    severity: "high",
    reason: "Database connection string with credentials",
  },
  {
    pattern: "mysql://[^:]+:[^@]+@",
    severity: "high",
    reason: "Database connection string with credentials",
  },
  {
    pattern: "mongodb(\\+srv)?://[^:]+:[^@]+@",
    severity: "high",
    reason: "MongoDB connection string with credentials",
  },
  {
    pattern: "eyJ[a-zA-Z0-9_-]{20,}\\.[a-zA-Z0-9_-]{20,}\\.[a-zA-Z0-9_-]{20,}",
    severity: "high",
    reason: "JWT token",
  },
  {
    pattern: "Bearer\\s+[A-Za-z0-9+/=_-]{20,}",
    severity: "high",
    reason: "Bearer token in content",
    flags: "i",
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
  {
    pattern: "\\.aws/credentials$",
    operations: ["read", "write", "delete", "git_add"],
    severity: "critical",
    reason: "AWS credentials file",
  },
  {
    pattern: "\\.ssh/authorized_keys$",
    operations: ["write", "delete", "git_add"],
    severity: "critical",
    reason: "SSH authorized keys file",
  },
  {
    pattern: "\\.docker/config\\.json$",
    operations: ["read", "write", "delete", "git_add"],
    severity: "high",
    reason: "Docker config with potential registry credentials",
  },
  {
    pattern: "\\.npmrc$",
    operations: ["read", "write", "delete", "git_add"],
    severity: "high",
    reason: "npm config with potential auth tokens",
  },
];
