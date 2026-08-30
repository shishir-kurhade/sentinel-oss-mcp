from __future__ import annotations

from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
GITLEAKS_IMAGE = (
    "ghcr.io/gitleaks/gitleaks@"
    "sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f"
)


@pytest.mark.parametrize("workflow_name", ["ci.yml", "release.yml"])
def test_full_history_secret_scan_is_explicit_and_digest_pinned(
    workflow_name: str,
) -> None:
    workflow = (REPOSITORY_ROOT / ".github" / "workflows" / workflow_name).read_text()

    assert "fetch-depth: 0" in workflow
    assert GITLEAKS_IMAGE in workflow
    assert "git --redact --verbose --log-opts=--all ." in workflow
    assert "gitleaks/gitleaks-action" not in workflow
    assert "Reject historical runtime data" in workflow
    assert "git rev-list --all --objects" in workflow
    assert "^[.]sentinel_cache\\//" in workflow
    assert '$2 == "assets/dashboard.png"' in workflow


def test_release_ref_and_supported_python_matrix_gate_secrets_and_publication() -> None:
    workflow = (REPOSITORY_ROOT / ".github" / "workflows" / "release.yml").read_text()

    assert 'test "$(git cat-file -t "refs/tags/${RELEASE_TAG}")" = "tag"' in workflow
    assert "git merge-base --is-ancestor" in workflow
    assert "'.verification.verified'" in workflow
    assert 'python-version: ["3.11", "3.12", "3.13"]' in workflow
    assert "needs: [offline-matrix, secret-scan]" in workflow
    assert "needs: [build]" in workflow
    assert "environment: release-live" in workflow


@pytest.mark.parametrize("workflow_name", ["ci.yml", "nightly-live.yml", "release.yml"])
def test_job_level_data_directory_does_not_use_runner_context(workflow_name: str) -> None:
    workflow = (REPOSITORY_ROOT / ".github" / "workflows" / workflow_name).read_text()

    assert "SENTINEL_DATA_DIR: /tmp/sentinel" in workflow
    assert "${{ runner.temp }}" not in workflow


def test_unconfigured_live_evaluation_is_manual_only() -> None:
    workflow = (REPOSITORY_ROOT / ".github" / "workflows" / "nightly-live.yml").read_text()

    assert "workflow_dispatch:" in workflow
    assert "schedule:" not in workflow


def test_dependabot_keeps_mcp_on_supported_major_version() -> None:
    configuration = (REPOSITORY_ROOT / ".github" / "dependabot.yml").read_text()

    assert "dependency-name: mcp" in configuration
    assert "version-update:semver-major" in configuration
