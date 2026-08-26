# Changelog

All notable changes to this project will be documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and releases use
[Semantic Versioning](https://semver.org/) with Python pre-release identifiers.

## [Unreleased]

### Added

- Contribution, security, privacy, threat-model, conduct, and release documentation.
- Offline CI for Python 3.11 through 3.13, dependency and source analysis, secret scanning,
  scheduled live evaluation, and Trusted Publishing release automation.

## [0.1.0b1] - Unreleased

### Added

- Typed `ExchangeRequest`, `ActionRequest`, and `SafetyDecision` contracts.
- Exchange-aware scanning with Unicode normalization, bounded inputs, reviewed signatures,
  optional semantic routing, and a structured classifier cascade.
- Deterministic action authorization using tool, argument, destination, data-label,
  provenance, reversibility, and confirmation rules.
- Versioned illustrative policy packs for banking, healthcare, telecom, retail, and HR/IT.
- Provider-neutral interfaces and an optional Gemini adapter.
- Metadata-only SQLite auditing and an optional aggregate dashboard.
- Local stdio MCP server plus evaluation and development red-team CLI commands.
- Deterministic offline tests and a 400-case synthetic evaluation corpus with a mandatory
  human-review manifest gate.
- Versioned aggregate evaluation reports with corpus provenance, attempted provider/model
  IDs, retry-aware token accounting, pricing provenance, and cost-coverage reporting.

### Changed

- Renamed the distribution to `sentinel-oss-mcp` and Python package to `sentinel_oss`.
- Replaced the prototype prompt waterfall with fail-safe exchange and action decisions.
- Made Gemini, vector, and dashboard dependency groups optional.
- Moved the default runtime to local stdio, lazy provider initialization, and privacy-safe
  platform data directories.

### Deprecated

- Prompt-only `check_safety(prompt, constitution)`, retained as a compatibility wrapper
  until `1.0.0`.

### Removed

- Raw interaction-log resources, runtime cache mutation, and red-team generation from the
  default MCP surface.
- Raw prompt persistence from core auditing.

### Security

- Errors, timeouts, malformed provider output, unknown policies, and oversized inputs now
  return `ERROR + REVIEW` rather than allowing by fallthrough.
- Semantic similarity is no longer an independent blocking authority.
- Unknown or malformed classifier rule references, low-confidence expert allows, invalid
  JSON numbers, nested denied arguments, and audit-write failures fail safely.
- Release automation rejects the known prototype cache and raw dashboard screenshot from
  every reachable Git ref in addition to running full-history credential scanning.

[Unreleased]: https://github.com/shishir-kurhade/sentinel-oss-mcp/compare/v0.1.0b1...HEAD
[0.1.0b1]: https://github.com/shishir-kurhade/sentinel-oss-mcp/releases/tag/v0.1.0b1
