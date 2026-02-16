import { loadPolicy } from "./policy";
import { validateAndAudit } from "./validator";
import type { HookInput, HookOutput } from "./types";

export async function handleHook(): Promise<void> {
  // Read stdin
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk as Buffer);
  }

  const raw = Buffer.concat(chunks).toString("utf-8").trim();
  if (!raw) {
    // Empty input — allow by default
    const output: HookOutput = { permissionDecision: "allow" };
    process.stdout.write(JSON.stringify(output) + "\n");
    return;
  }

  let input: HookInput;
  try {
    input = JSON.parse(raw) as HookInput;
  } catch {
    // Unparseable input — allow by default (don't block on parse errors)
    const output: HookOutput = { permissionDecision: "allow" };
    process.stdout.write(JSON.stringify(output) + "\n");
    return;
  }

  const cwd = input.cwd ?? process.cwd();

  try {
    const policy = loadPolicy(cwd);
    const result = validateAndAudit(input, policy, cwd);

    const output: HookOutput = {
      permissionDecision: result.allowed ? "allow" : "deny",
    };

    if (!result.allowed && result.reason) {
      output.reason = `[Guardian] ${result.reason}`;
    }

    process.stdout.write(JSON.stringify(output) + "\n");
  } catch (err) {
    // Policy load error or validation error — allow by default (fail open)
    // Log to stderr so the error is visible but doesn't block
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(`Guardian error: ${message}\n`);
    const output: HookOutput = { permissionDecision: "allow" };
    process.stdout.write(JSON.stringify(output) + "\n");
  }
}
