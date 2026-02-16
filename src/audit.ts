import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";
import type { Policy, AuditEntry, ValidationResult, HookInput, Severity } from "./types";

let lastHash: string = "";
let sequenceNumber: number = 0;

function computeHash(prevHash: string, entryWithoutHash: Omit<AuditEntry, "hash">): string {
  const payload = prevHash + JSON.stringify(entryWithoutHash);
  return "sha256:" + crypto.createHash("sha256").update(payload).digest("hex");
}

function getAuditPath(policy: Policy, cwd: string): string {
  return path.resolve(cwd, policy.audit.path);
}

function shouldRotate(policy: Policy, auditPath: string): boolean {
  if (!fs.existsSync(auditPath)) return false;

  // Size-based rotation
  const stat = fs.statSync(auditPath);
  const sizeMb = stat.size / (1024 * 1024);
  if (sizeMb >= policy.audit.max_file_size_mb) return true;

  // Daily rotation
  if (policy.audit.rotation === "daily") {
    const today = new Date().toISOString().split("T")[0];
    const fileDate = stat.mtime.toISOString().split("T")[0];
    if (today !== fileDate) return true;
  }

  return false;
}

function rotateAuditFile(auditPath: string): void {
  const date = new Date().toISOString().split("T")[0];
  const dir = path.dirname(auditPath);
  const ext = path.extname(auditPath);
  const base = path.basename(auditPath, ext);
  const rotatedPath = path.join(dir, `${base}.${date}${ext}`);

  // Avoid overwriting existing rotated file
  let finalPath = rotatedPath;
  let counter = 1;
  while (fs.existsSync(finalPath)) {
    finalPath = path.join(dir, `${base}.${date}.${counter}${ext}`);
    counter++;
  }

  fs.renameSync(auditPath, finalPath);

  // Reset sequence and hash for new file
  sequenceNumber = 0;
  lastHash = "";
}

export function writeAuditEntry(
  input: HookInput,
  result: ValidationResult,
  policy: Policy,
  cwd: string,
  budgetState: { remaining_usd: number | null; action_count: number } | null
): void {
  if (!policy.audit.enabled) return;

  const auditPath = getAuditPath(policy, cwd);

  // Ensure directory exists
  const auditDir = path.dirname(auditPath);
  if (!fs.existsSync(auditDir)) {
    fs.mkdirSync(auditDir, { recursive: true });
  }

  // Check rotation
  if (shouldRotate(policy, auditPath)) {
    rotateAuditFile(auditPath);
  }

  // Initialize sequence from existing file
  if (sequenceNumber === 0 && fs.existsSync(auditPath)) {
    const content = fs.readFileSync(auditPath, "utf-8").trim();
    if (content) {
      const lines = content.split("\n");
      const lastLine = lines[lines.length - 1];
      if (lastLine) {
        try {
          const lastEntry = JSON.parse(lastLine) as AuditEntry;
          sequenceNumber = lastEntry.seq;
          lastHash = lastEntry.hash;
        } catch {
          // Corrupted last line — start fresh sequence
        }
      }
    }
  }

  sequenceNumber++;

  const entryWithoutHash: Omit<AuditEntry, "hash"> = {
    v: 1,
    ts: new Date().toISOString(),
    sid: input.session_id ?? "unknown",
    seq: sequenceNumber,
    tool: input.tool_name,
    input: policy.audit.include_tool_input ? input.tool_input : null,
    allowed: result.allowed,
    reason: result.reason,
    severity: result.severity,
    policy_match: result.pattern,
    budget: budgetState,
    cwd,
  };

  const hash = policy.audit.integrity === "sha256-chain"
    ? computeHash(lastHash, entryWithoutHash)
    : "none";

  const entry: AuditEntry = { ...entryWithoutHash, hash };
  lastHash = hash;

  fs.appendFileSync(auditPath, JSON.stringify(entry) + "\n");
}

export function verifyAuditChain(auditPath: string): { valid: boolean; entries: number; brokenAt: number | null } {
  if (!fs.existsSync(auditPath)) {
    return { valid: true, entries: 0, brokenAt: null };
  }

  const content = fs.readFileSync(auditPath, "utf-8").trim();
  if (!content) return { valid: true, entries: 0, brokenAt: null };

  const lines = content.split("\n");
  let prevHash = "";

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    let entry: AuditEntry;

    try {
      entry = JSON.parse(line) as AuditEntry;
    } catch {
      return { valid: false, entries: i, brokenAt: i + 1 };
    }

    // Reconstruct hash
    const { hash, ...rest } = entry;
    const expectedHash = computeHash(prevHash, rest);

    if (hash !== expectedHash) {
      return { valid: false, entries: lines.length, brokenAt: i + 1 };
    }

    prevHash = hash;
  }

  return { valid: true, entries: lines.length, brokenAt: null };
}

export function getAuditSummary(auditPath: string): {
  total: number;
  allowed: number;
  denied: number;
  byTool: Record<string, number>;
  bySeverity: Record<string, number>;
} {
  const summary = {
    total: 0,
    allowed: 0,
    denied: 0,
    byTool: {} as Record<string, number>,
    bySeverity: {} as Record<string, number>,
  };

  if (!fs.existsSync(auditPath)) return summary;

  const content = fs.readFileSync(auditPath, "utf-8").trim();
  if (!content) return summary;

  for (const line of content.split("\n")) {
    try {
      const entry = JSON.parse(line) as AuditEntry;
      summary.total++;
      if (entry.allowed) summary.allowed++;
      else summary.denied++;
      summary.byTool[entry.tool] = (summary.byTool[entry.tool] ?? 0) + 1;
      if (entry.severity) {
        summary.bySeverity[entry.severity] = (summary.bySeverity[entry.severity] ?? 0) + 1;
      }
    } catch {
      // Skip corrupt lines
    }
  }

  return summary;
}

export function resetAuditState(): void {
  lastHash = "";
  sequenceNumber = 0;
}
