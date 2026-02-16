import type { Policy, ValidationResult, Severity, HookInput } from "./types";

interface CompiledPattern {
  regex: RegExp;
  severity: Severity;
  reason: string;
  source: string;
}

let compiledPatterns: Map<string, CompiledPattern[]> | null = null;

function compilePatterns(policy: Policy): Map<string, CompiledPattern[]> {
  const map = new Map<string, CompiledPattern[]>();

  // Command patterns
  const commands: CompiledPattern[] = policy.blocklist.commands.map((p) => ({
    regex: new RegExp(p.pattern, p.flags ?? ""),
    severity: p.severity,
    reason: p.reason,
    source: p.pattern,
  }));
  map.set("commands", commands);

  // File patterns
  const files: CompiledPattern[] = policy.blocklist.file_patterns.map((p) => ({
    regex: new RegExp(p.pattern),
    severity: p.severity,
    reason: p.reason,
    source: p.pattern,
  }));
  map.set("file_patterns", files);

  // Secret patterns
  const secrets: CompiledPattern[] = policy.blocklist.secret_patterns.map((p) => ({
    regex: new RegExp(p.pattern, p.flags ?? ""),
    severity: p.severity,
    reason: p.reason,
    source: p.pattern,
  }));
  map.set("secret_patterns", secrets);

  // Network patterns
  const network: CompiledPattern[] = policy.blocklist.network.map((p) => ({
    regex: new RegExp(p.pattern),
    severity: p.severity,
    reason: p.reason,
    source: p.pattern,
  }));
  map.set("network", network);

  return map;
}

function getPatterns(policy: Policy): Map<string, CompiledPattern[]> {
  if (!compiledPatterns) {
    compiledPatterns = compilePatterns(policy);
  }
  return compiledPatterns;
}

/** Split a shell command on &&, ||, ;, and | to get individual segments */
function splitShellCommand(command: string): string[] {
  const segments: string[] = [];
  let current = "";
  let depth = 0; // Track $() and () depth
  let inSingle = false;
  let inDouble = false;

  for (let i = 0; i < command.length; i++) {
    const ch = command[i]!;
    const next = command[i + 1];

    // Track quotes
    if (ch === "'" && !inDouble) { inSingle = !inSingle; current += ch; continue; }
    if (ch === '"' && !inSingle) { inDouble = !inDouble; current += ch; continue; }

    if (inSingle || inDouble) { current += ch; continue; }

    // Track subshell depth
    if (ch === "(" || (ch === "$" && next === "(")) { depth++; current += ch; continue; }
    if (ch === ")") { depth = Math.max(0, depth - 1); current += ch; continue; }

    // Only split at top level
    if (depth > 0) { current += ch; continue; }

    // Split on && || ; |
    if (ch === "&" && next === "&") { segments.push(current.trim()); current = ""; i++; continue; }
    if (ch === "|" && next === "|") { segments.push(current.trim()); current = ""; i++; continue; }
    if (ch === ";") { segments.push(current.trim()); current = ""; continue; }
    if (ch === "|") { segments.push(current.trim()); current = ""; continue; }

    current += ch;
  }

  if (current.trim()) segments.push(current.trim());
  return segments.filter(Boolean);
}

/** Extract $() and backtick subcommands */
function extractSubcommands(command: string): string[] {
  const subs: string[] = [];

  // Match $(...) — handle nesting
  let depth = 0;
  let start = -1;
  for (let i = 0; i < command.length - 1; i++) {
    if (command[i] === "$" && command[i + 1] === "(") {
      if (depth === 0) start = i + 2;
      depth++;
      i++;
    } else if (command[i] === ")" && depth > 0) {
      depth--;
      if (depth === 0 && start >= 0) {
        subs.push(command.substring(start, i));
        start = -1;
      }
    }
  }

  // Match backticks (non-nested)
  const backtickMatch = command.match(/`([^`]+)`/g);
  if (backtickMatch) {
    for (const m of backtickMatch) {
      subs.push(m.slice(1, -1));
    }
  }

  return subs;
}

/** Strip content inside single and double quotes, leaving only unquoted portions */
export function stripQuotedStrings(text: string): string {
  let result = '';
  let inSingle = false;
  let inDouble = false;

  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!;

    // Handle escape sequences (only in double quotes)
    if (ch === '\\' && inDouble && i + 1 < text.length) {
      i++; // skip escaped char
      continue;
    }

    if (ch === "'" && !inDouble) {
      inSingle = !inSingle;
      continue;
    }
    if (ch === '"' && !inSingle) {
      inDouble = !inDouble;
      continue;
    }

    if (!inSingle && !inDouble) {
      result += ch;
    }
  }

  return result;
}

function matchPatterns(text: string, patterns: CompiledPattern[]): CompiledPattern | null {
  for (const p of patterns) {
    p.regex.lastIndex = 0;
    if (p.regex.test(text)) {
      return p;
    }
  }
  return null;
}

export function checkBlocklist(input: HookInput, policy: Policy): ValidationResult | null {
  const patterns = getPatterns(policy);
  const tool = input.tool_name;
  const toolInput = input.tool_input;

  // --- Bash command checks ---
  if (tool === "Bash") {
    const command = (toolInput.command as string) ?? "";

    // Check full command string (stripped of quoted content to prevent false positives)
    const cmdPatterns = patterns.get("commands") ?? [];
    const strippedCommand = stripQuotedStrings(command);
    const fullMatch = matchPatterns(strippedCommand, cmdPatterns);
    if (fullMatch) {
      return { allowed: false, reason: fullMatch.reason, severity: fullMatch.severity, pattern: fullMatch.source, source: "blocklist" };
    }

    // Check each shell segment (stripped of quoted content)
    const segments = splitShellCommand(command);
    for (const seg of segments) {
      const strippedSeg = stripQuotedStrings(seg);
      const segMatch = matchPatterns(strippedSeg, cmdPatterns);
      if (segMatch) {
        return { allowed: false, reason: segMatch.reason, severity: segMatch.severity, pattern: segMatch.source, source: "blocklist" };
      }
    }

    // Check subcommands
    const subcommands = extractSubcommands(command);
    for (const sub of subcommands) {
      const subMatch = matchPatterns(sub, cmdPatterns);
      if (subMatch) {
        return { allowed: false, reason: subMatch.reason, severity: subMatch.severity, pattern: subMatch.source, source: "blocklist" };
      }
    }

    // Check network patterns in curl/wget commands
    const netPatterns = patterns.get("network") ?? [];
    const netMatch = matchPatterns(command, netPatterns);
    if (netMatch) {
      return { allowed: false, reason: netMatch.reason, severity: netMatch.severity, pattern: netMatch.source, source: "blocklist" };
    }

    return null;
  }

  // --- Write/Edit file and content checks ---
  if (tool === "Write" || tool === "Edit") {
    const filePath = (toolInput.file_path as string) ?? "";
    const filePatterns = patterns.get("file_patterns") ?? [];

    // Check file path
    for (const p of filePatterns) {
      p.regex.lastIndex = 0;
      if (p.regex.test(filePath)) {
        const fp = policy.blocklist.file_patterns.find((fp) => fp.pattern === p.source);
        if (fp && fp.operations.includes("write")) {
          return { allowed: false, reason: p.reason, severity: p.severity, pattern: p.source, source: "blocklist" };
        }
      }
    }

    // Check content for secrets
    const content = (toolInput.content as string) ?? (toolInput.new_string as string) ?? "";
    if (content) {
      const secretPatterns = patterns.get("secret_patterns") ?? [];
      const secretMatch = matchPatterns(content, secretPatterns);
      if (secretMatch) {
        return { allowed: false, reason: secretMatch.reason, severity: secretMatch.severity, pattern: secretMatch.source, source: "blocklist" };
      }
    }

    return null;
  }

  // --- Read file checks ---
  if (tool === "Read") {
    const filePath = (toolInput.file_path as string) ?? "";
    const filePatterns = patterns.get("file_patterns") ?? [];

    for (const p of filePatterns) {
      p.regex.lastIndex = 0;
      if (p.regex.test(filePath)) {
        const fp = policy.blocklist.file_patterns.find((fp) => fp.pattern === p.source);
        if (fp && fp.operations.includes("read")) {
          return { allowed: false, reason: p.reason, severity: p.severity, pattern: p.source, source: "blocklist" };
        }
      }
    }

    return null;
  }

  // --- WebFetch URL checks ---
  if (tool === "WebFetch") {
    const url = (toolInput.url as string) ?? "";
    const netPatterns = patterns.get("network") ?? [];
    const netMatch = matchPatterns(url, netPatterns);
    if (netMatch) {
      return { allowed: false, reason: netMatch.reason, severity: netMatch.severity, pattern: netMatch.source, source: "blocklist" };
    }

    return null;
  }

  // --- MCP tools: extract and check command-like inputs ---
  if (tool.startsWith("mcp__")) {
    const cmdPatterns = patterns.get("commands") ?? [];
    const netPatterns = patterns.get("network") ?? [];
    const secretPatterns = patterns.get("secret_patterns") ?? [];

    // Check all string values in tool input
    for (const value of Object.values(toolInput)) {
      if (typeof value === "string") {
        const cmdMatch = matchPatterns(value, cmdPatterns);
        if (cmdMatch) {
          return { allowed: false, reason: cmdMatch.reason, severity: cmdMatch.severity, pattern: cmdMatch.source, source: "blocklist" };
        }
        const netMatch = matchPatterns(value, netPatterns);
        if (netMatch) {
          return { allowed: false, reason: netMatch.reason, severity: netMatch.severity, pattern: netMatch.source, source: "blocklist" };
        }
        const secretMatch = matchPatterns(value, secretPatterns);
        if (secretMatch) {
          return { allowed: false, reason: secretMatch.reason, severity: secretMatch.severity, pattern: secretMatch.source, source: "blocklist" };
        }
      }
    }

    return null;
  }

  // No blocklist for Glob, Grep, Task, WebSearch, etc.
  return null;
}

export function resetCompiledPatterns(): void {
  compiledPatterns = null;
}
