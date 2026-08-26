## Summary

<!-- What problem does this solve, and why is this approach appropriate? -->

## Security and privacy impact

<!-- Describe decision-path, policy, data-flow, dependency, and threat-model changes. -->

- [ ] No new content, output, argument, embedding, payload hash, or credential is persisted.
- [ ] Errors and ambiguous states cannot become `ALLOW`.
- [ ] Public messages and fixtures contain only synthetic, non-sensitive data.
- [ ] New dependencies or network calls are justified and documented.

## Validation

<!-- List exact offline tests, evaluation cases, and manual checks performed. -->

- [ ] Ruff lint and format checks pass.
- [ ] Mypy passes.
- [ ] Offline tests pass on supported Python versions.
- [ ] Relevant harmful, benign, hard-negative, and failure cases were added.
- [ ] Public contracts and changelog were updated when needed.

## Compatibility

<!-- Note deprecations, migrations, policy-version changes, and optional-extra impact. -->
