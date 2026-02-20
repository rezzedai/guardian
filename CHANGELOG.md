# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-02-20

### Added
- Initial release
- Safety rails for AI agent sessions
- Blocklist patterns for destructive commands, privilege escalation, secret leaks, exfiltration, and supply chain attacks
- Scope enforcement for file operations
- Budget enforcement (action count and cost limits)
- Tamper-proof audit trail with SHA256-chain integrity
- Kill switch for critical violations
- CLI commands: init, validate, check, audit, test, budget
- Zero runtime dependencies
- Comprehensive test suite and CI workflow
- MIT LICENSE

### Changed
- Updated npm scope from `@rezzedai` to `@rezzed.ai`
- Dropped Node 18 from CI test matrix (EOL since April 2025)
- Sanitized README to remove internal references

### Fixed
- Prevented false positives on patterns inside quoted strings

[0.1.0]: https://github.com/rezzedai/guardian/releases/tag/v0.1.0
