import * as fs from "fs";
import * as path from "path";
import type { Policy } from "./types";

let cachedPolicy: Policy | null = null;
let cachedPolicyPath: string | null = null;
let cachedMtime: number = 0;

const REQUIRED_FIELDS = ["version", "mode", "blocklist", "allowlist", "scope", "audit", "kill_switch"];
const VALID_MODES = ["enforce", "audit", "off"];

export function loadPolicy(cwd: string): Policy {
  const policyPath = path.join(cwd, ".guardian", "policy.json");

  // Cache check: return cached if file hasn't changed
  if (cachedPolicy && cachedPolicyPath === policyPath) {
    try {
      const stat = fs.statSync(policyPath);
      if (stat.mtimeMs === cachedMtime) {
        return cachedPolicy;
      }
    } catch {
      // File changed or disappeared, reload
    }
  }

  if (!fs.existsSync(policyPath)) {
    throw new Error(`Policy file not found: ${policyPath}. Run 'guardian init' to create one.`);
  }

  const raw = fs.readFileSync(policyPath, "utf-8");
  let parsed: unknown;

  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    throw new Error(`Invalid JSON in policy file: ${message}`);
  }

  const policy = parsed as Record<string, unknown>;

  // Validate required fields
  for (const field of REQUIRED_FIELDS) {
    if (!(field in policy)) {
      throw new Error(`Policy missing required field: ${field}`);
    }
  }

  if (policy.version !== 1) {
    throw new Error(`Unsupported policy version: ${policy.version}. Expected 1.`);
  }

  if (!VALID_MODES.includes(policy.mode as string)) {
    throw new Error(`Invalid policy mode: ${policy.mode}. Expected: ${VALID_MODES.join(", ")}`);
  }

  // Cache the validated policy
  const validatedPolicy = policy as unknown as Policy;
  cachedPolicy = validatedPolicy;
  cachedPolicyPath = policyPath;

  try {
    cachedMtime = fs.statSync(policyPath).mtimeMs;
  } catch {
    cachedMtime = 0;
  }

  return validatedPolicy;
}

export function getDefaultPolicyPath(): string {
  return path.join(__dirname, "..", ".guardian", "policy.default.json");
}

export function resetCache(): void {
  cachedPolicy = null;
  cachedPolicyPath = null;
  cachedMtime = 0;
}
