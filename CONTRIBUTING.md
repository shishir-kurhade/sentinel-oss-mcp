# Contributing to Sentinel OSS MCP

Thank you for helping make Sentinel easier to audit and safer to integrate. By
participating, you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Before opening an issue

- Use a [private vulnerability report](SECURITY.md) for suspected vulnerabilities,
  bypasses involving non-public payloads, leaked credentials, or sensitive data.
- Search existing issues before opening a public bug or feature request.
- Do not include real prompts, customer data, credentials, personal data, or raw audit
  databases in issues, fixtures, screenshots, or pull requests.
- Discuss large interface, policy-schema, or dependency changes in an issue first.

## Development setup

Sentinel supports Python 3.11, 3.12, and 3.13. Create an isolated environment and install
the editable package:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

Provider, vector, and dashboard dependencies are optional. Add only the extra needed for
the change you are testing, for example `.[dev,gemini]`.

## Required checks

Run the same offline checks used by pull-request CI:

```bash
ruff check .
ruff format --check .
mypy src/sentinel_oss
pytest -m "not live" --cov=sentinel_oss --cov-report=term-missing
python -m build
python -m twine check dist/*
```

Unit and integration tests must not require network access, cloud credentials, an existing
database, or wall-clock timing. Inject deterministic fake providers/embedders and use a
temporary directory for runtime state. Mark any explicitly approved provider test with
`@pytest.mark.live`; live tests do not run on ordinary pull requests.

## Security invariants

Changes must preserve these invariants:

- An exception, timeout, malformed classifier response, unknown policy, or oversized input
  never produces `ALLOW`.
- Only `status=COMPLETE, outcome=ALLOW` authorizes a caller to continue.
- Semantic similarity can route or escalate, but cannot independently block.
- Confirmation can satisfy an approval rule, but cannot override a hard block.
- Runtime auditing does not persist prompts, outputs, arguments, embeddings, or payload
  hashes.
- Public error messages and logs do not echo untrusted or sensitive input.
- Imports, schema discovery, help output, and offline tests work without credentials.

Add regression tests for every change to decision precedence or a fail-safe path. A policy
change needs harmful, benign, and hard-negative cases plus a stable rule ID and version
update.

## Evaluation data

Evaluation fixtures must be synthetic, reviewable, and safe to publish. Do not copy private
incident payloads or proprietary benchmark data. Each case should state its expected
outcome, policy/domain, category, and whether it is a critical regression. Keep evaluators
deterministic and do not modify expected labels merely to make a model score pass.

Live model results are inherently variable. A live result may inform threshold calibration,
but a deterministic regression should capture any accepted behavior change.

## Pull requests

Keep pull requests focused and include:

- the problem and threat scenario;
- the behavior before and after the change;
- tests and evaluation cases added;
- privacy, compatibility, dependency, and performance impact;
- documentation or changelog updates when a public contract changes.

Use clear commit messages. By submitting a contribution, you agree that it is licensed
under the repository's Apache-2.0 license and that you have the right to contribute it.

Maintainers may request changes when a contribution expands the threat model or dependency
surface without a corresponding test and rationale.
