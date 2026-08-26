# Security policy

Sentinel is security-sensitive beta software. Please report vulnerabilities privately and
do not rely on Sentinel as your only control for an agent or tool.

## Supported versions

Security fixes are provided for the latest published beta or stable release and the
default branch. Prototype versions before `0.1.0b1` are unsupported and may persist raw
interaction data.

| Version | Supported |
| --- | --- |
| Latest `0.1.x` beta | Yes |
| Default branch | Best effort |
| Earlier prototypes | No |

## Report a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/shishir-kurhade/sentinel-oss-mcp/security/advisories/new).
Do not open a public issue for a suspected vulnerability.

Include, where possible:

- the affected release, commit, Python version, and optional extras;
- a minimal synthetic reproduction with secrets and personal data removed;
- expected and observed decisions, including reason codes and stages;
- impact, preconditions, and whether the caller correctly enforced `REVIEW`;
- suggested mitigations or a patch, if available.

Do not send live credentials, customer data, production prompts, raw audit databases, or
provider responses. If a reproduction needs sensitive material, first ask the maintainer
for an appropriate secure transfer method without including the material itself.

The maintainers target an initial acknowledgement within three business days and a triage
update within seven, but these are goals rather than a service-level agreement. A report
may be coordinated through a GitHub security advisory until a fix and disclosure are
ready.

## What counts as a security issue

Examples include:

- a failure path that returns `COMPLETE + ALLOW` after malformed output, timeout, provider
  error, unknown policy, or invalid request;
- deterministic action-rule precedence that permits a hard-blocked operation;
- persistence or disclosure of prompt text, model output, tool arguments, embeddings,
  credentials, or personal data;
- arbitrary file access, command execution, SQL injection, or path traversal;
- a remotely reachable transport unexpectedly enabled by the default server;
- a dependency or build/release compromise;
- a reproducible policy bypass with meaningful impact under the documented threat model.

Model disagreement on an ambiguous prompt, use outside the documented threat model, and a
caller ignoring a `BLOCK`, `REVIEW`, or `ERROR` decision are generally product-quality or
integration issues rather than vulnerabilities. When uncertain, report privately.

## Coordinated disclosure

Please allow a reasonable remediation window before public disclosure. Maintainers will
credit reporters who request attribution. Good-faith research using synthetic data,
without privacy violations, persistence, service disruption, or unauthorized access, is
welcome.

## Operational guidance

- Pin and verify releases; review dependency and provenance information.
- Run the MCP server locally over stdio with least-privileged filesystem and network access.
- Do not expose the beta server directly to a network.
- Keep model credentials out of command arguments, repository files, and logs.
- Validate caller-declared provenance and enforce Sentinel's decision immediately before
  the action.
- Treat every result except `status=COMPLETE, outcome=ALLOW` as not authorized.
- Review and test the illustrative policy packs for your environment.

See [THREAT_MODEL.md](THREAT_MODEL.md) and [PRIVACY.md](PRIVACY.md) for the boundaries that
shape security triage.
