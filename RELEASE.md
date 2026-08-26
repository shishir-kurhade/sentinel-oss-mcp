# Release process

This checklist is for maintainers. A release is not complete until its source, wheel,
GitHub release, PyPI record, and documented evaluation report refer to the same commit and
version.

## One-time repository preparation

Before the first public beta:

1. Enable GitHub private vulnerability reporting, secret scanning, push protection,
   Dependabot alerts, branch protection, required reviews, and required CI checks.
2. Configure a PyPI Trusted Publisher for repository
   `shishir-kurhade/sentinel-oss-mcp`, workflow `release.yml`, environment `pypi`. Do not
   create or store a long-lived PyPI API token.
3. Protect the `pypi` environment with required reviewers and restrict it to version tags.
4. Create a `nightly-live` environment restricted to the protected default branch, and a
   `release-live` environment restricted to version tags with required human reviewers.
   Store `GOOGLE_API_KEY` only as an environment secret in both; do not expose it as a
   repository-level secret. The release workflow completes its credential-free history,
   review, test, audit, and build gates before it enters `release-live`.
5. Configure these GitHub environment variables in both live environments:
   `SENTINEL_LIGHTWEIGHT_INPUT_PRICE_PER_MILLION`,
   `SENTINEL_LIGHTWEIGHT_OUTPUT_PRICE_PER_MILLION`,
   `SENTINEL_EXPERT_INPUT_PRICE_PER_MILLION`, and
   `SENTINEL_EXPERT_OUTPUT_PRICE_PER_MILLION`. Also set
   `SENTINEL_EVAL_PRICE_SOURCE_URL` to the public HTTPS official source and
   `SENTINEL_EVAL_PRICE_ACCESSED_AT` to its `YYYY-MM-DD` verification date. Resolve the
   USD-per-million-token rates from that source for the exact configured models; the live
   report records all six values. Prices are intentionally not
   hardcoded; re-check them before every release candidate. Protected live jobs set
   `SENTINEL_OFFLINE=0`; offline test jobs set `SENTINEL_OFFLINE=1` so credentials cannot
   accidentally activate a provider.
6. Review permissions of every GitHub Action and pin actions to reviewed commit SHAs when
   the repository's dependency-update process is ready to maintain those pins.
7. Protect `main` with pull-request reviews and required CI, and create a `v*` tag ruleset
   that limits tag creation to release maintainers. The workflow additionally rejects a
   tag unless it is annotated, GitHub reports its signature as verified, its target is an
   ancestor of `origin/main`, and that exact target passes the Python 3.11-3.13 matrix.
   Keep the release workflow itself under required code-owner review.
8. Confirm that `sentinel-oss-mcp` is available and that the README, project URLs, and
   security contact resolve publicly.

### Remove prototype runtime data from history

The prototype committed `.sentinel_cache` files that may contain raw interactions and an
`assets/dashboard.png` screenshot containing an interaction-history table with raw prompts.
Removing the current-tree copies is not sufficient. This destructive, owner-coordinated
history rewrite must happen before the repository is announced publicly.

1. Freeze pushes and notify every collaborator that commit hashes will change.
2. Create an encrypted, access-restricted mirror backup outside the working repository.
   Retain it only as long as incident and legal review requires.
3. Inspect the data and complete any required privacy or incident response.
4. Use a reviewed `git filter-repo` invocation to remove both `.sentinel_cache` and
   `assets/dashboard.png` from every ref.
5. Run a full-history secret scan on the rewritten mirror and inspect all findings.
6. Have a second maintainer verify that both paths and their sensitive blobs are unreachable
   from every branch, tag, pull-request ref under project control, and generated archive.
7. Coordinate a force-push of rewritten branches and tags, then instruct collaborators to
   re-clone. Do not merge old-history branches afterward.
8. Request cache invalidation from hosting or archival services if incident review requires
   it. History rewriting does not erase existing clones, forks, logs, or external caches.

Do not paste a generic history-rewrite command without resolving and reviewing the exact
repository, refs, backup path, and retention requirements.

## Release gates

For the candidate commit, require:

- offline CI on Python 3.11, 3.12, and 3.13;
- a GitHub-verified signed annotated tag targeting the protected default branch;
- no error, timeout, malformed response, unknown policy, or oversized input becoming
  `ALLOW`;
- all designated critical content and action regressions passing;
- at least 95% harmful recall overall and 90% in every illustrative domain;
- at most 5% benign false positives and 10% hard-negative false positives;
- at least 90% line/branch coverage overall and 95% for decision routing and error paths;
- a successful clean wheel and source build, metadata check, isolated install, import,
  console help, and MCP handshake;
- no credentials or runtime databases in the tree, history, artifacts, or logs;
- no unapproved high or critical source/dependency findings;
- a reviewed live Gemini report generated from the tagged evaluation corpus;
- an `APPROVED` human-review manifest whose SHA-256 values match both corpus files;
- complete classifier cost coverage for every provider attempt, including retries, whenever
  the live run makes at least one provider request;
- complete pricing provenance containing all four rates, the official HTTPS source, and its
  access date;
- review of `SECURITY.md`, `PRIVACY.md`, `THREAT_MODEL.md`, and all public claims.

Record the model IDs, policy versions, corpus commit, environment, result schema version,
latency distribution, `provider_attempts`, token and cost coverage, estimated cost, dated
official price source, and date with a live report. `model_calls` is the compatibility name
for actual classifier attempts and includes retries. The release workflow disables semantic
routing; embedding usage and cost are outside the report's scope. Do not publish a score or
an incomplete cost total without its versioned report and limitations.

## Prepare a release

1. Start from a clean, protected default branch and update dependencies intentionally.
2. Set the same PEP 440 version in `pyproject.toml`, package `__version__`, changelog heading,
   and intended tag (`v0.1.0b1` for the first beta).
3. Move completed changelog entries under the version with the release date. Do not claim
   unreleased or unverified behavior.
4. Run the offline checks documented in `CONTRIBUTING.md` and inspect wheel contents:

   ```bash
   python -m build
   python -m twine check dist/*
   python -m zipfile --list dist/*.whl
   ```

5. Install the wheel into a new environment with no provider credentials. Verify imports,
   both console commands' help, policy discovery, and fail-safe behavior.
6. Install each optional extra in isolation and verify lazy initialization.
7. Generate and review the release-candidate live evaluation report through the protected
   workflow. Confirm all four pricing repository variables still match a dated official
   source before dispatch. Never run provider-backed evaluation on a fork pull request.
8. Record the human corpus review in `src/sentinel_oss/eval_data/review.json`; the release
   workflow must verify its reviewer, timestamp, and file hashes before provider calls.
9. Obtain maintainer approval for the changelog, artifacts, evaluation, security findings,
   and migration notes.

## Publish and verify

1. Create and push the signed annotated version tag from the approved commit.
2. The `release.yml` workflow validates the tag/version, reruns release checks, builds once,
   attests artifacts, publishes through PyPI Trusted Publishing, and creates a prerelease or
   release on GitHub.
3. Verify hashes and metadata on both PyPI and GitHub. Install from PyPI into clean Python
   3.11 and 3.13 environments and repeat the smoke tests.
4. Confirm the GitHub release links the changelog, evaluation report, threat-model changes,
   known limitations, and upgrade instructions.
5. Announce only after verification. Monitor private reports, install failures, and provider
   regressions; yank a broken artifact rather than silently replacing it.

Release artifacts are immutable. Fixes require a new version.
