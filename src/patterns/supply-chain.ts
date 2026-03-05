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
  {
    pattern: "pip\\s+install\\s+.*--index-url\\s+(?!https://pypi\\.org)",
    severity: "medium",
    reason: "pip install from non-standard index",
  },
  {
    pattern: "gem\\s+install\\s+.*--source\\s+(?!https://rubygems\\.org)",
    severity: "medium",
    reason: "gem install from non-standard source",
  },
  {
    pattern: "cargo\\s+install\\s+--git\\s+(?!https://github\\.com)",
    severity: "medium",
    reason: "cargo install from non-GitHub git source",
  },
  {
    pattern: "go\\s+get\\s+-u\\s+(?!github\\.com|golang\\.org)",
    severity: "medium",
    reason: "go get from potentially untrusted source",
  },
  {
    pattern: "apt-get\\s+install\\s+(?!.*--no-install-recommends).*[^=]$",
    severity: "low",
    reason: "apt-get install without version pinning",
  },
  {
    pattern: "docker\\s+pull\\s+(?!docker\\.io|ghcr\\.io|gcr\\.io)",
    severity: "medium",
    reason: "docker pull from non-standard registry",
  },
];
