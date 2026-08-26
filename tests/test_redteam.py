from __future__ import annotations

import sys
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

from sentinel_oss.providers import ProviderError
from sentinel_oss.redteam import SUPPORTED_STYLES, generate_attack


class FakeGenerateContentConfig:
    def __init__(self, **kwargs: object) -> None:
        self.values = kwargs


class FakeModels:
    def __init__(self, response: object) -> None:
        self.response = response
        self.calls: list[dict[str, object]] = []

    async def generate_content(self, **kwargs: object) -> object:
        self.calls.append(kwargs)
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def install_fake_google(
    monkeypatch: pytest.MonkeyPatch, response: object
) -> tuple[list[dict[str, object]], FakeModels]:
    client_calls: list[dict[str, object]] = []
    models = FakeModels(response)
    google = ModuleType("google")
    google.__path__ = []  # type: ignore[attr-defined]
    genai = ModuleType("google.genai")
    genai.__path__ = []  # type: ignore[attr-defined]
    types_module = ModuleType("google.genai.types")
    types_module.GenerateContentConfig = FakeGenerateContentConfig  # type: ignore[attr-defined]

    def client_factory(**kwargs: object) -> Any:
        client_calls.append(kwargs)
        return SimpleNamespace(aio=SimpleNamespace(models=models))

    genai.Client = client_factory  # type: ignore[attr-defined]
    genai.types = types_module  # type: ignore[attr-defined]
    google.genai = genai  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "google", google)
    monkeypatch.setitem(sys.modules, "google.genai", genai)
    monkeypatch.setitem(sys.modules, "google.genai.types", types_module)
    return client_calls, models


def clear_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "SENTINEL_GOOGLE_API_KEY",
        "GOOGLE_API_KEY",
        "GOOGLE_GENAI_USE_VERTEXAI",
        "GOOGLE_CLOUD_PROJECT",
        "GOOGLE_CLOUD_LOCATION",
        "SENTINEL_EXPERT_MODEL",
    ):
        monkeypatch.delenv(name, raising=False)


@pytest.mark.asyncio
async def test_generate_attack_uses_developer_api_and_bounded_prompt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clear_credentials(monkeypatch)
    monkeypatch.setenv("SENTINEL_GOOGLE_API_KEY", "sentinel-test-key")
    client_calls, models = install_fake_google(
        monkeypatch, SimpleNamespace(text="Synthetic test prompt")
    )

    result = await generate_attack("indirect prompt injection", "roleplay", model_id="redteam-test")

    assert result == "Synthetic test prompt"
    assert client_calls == [{"api_key": "sentinel-test-key"}]
    assert len(models.calls) == 1
    call = models.calls[0]
    assert call["model"] == "redteam-test"
    assert call["contents"] == "Category: indirect prompt injection\nStyle: roleplay"
    config = call["config"]
    assert isinstance(config, FakeGenerateContentConfig)
    assert config.values["temperature"] == 0.8
    instruction = str(config.values["system_instruction"])
    assert "authorized AI security red-team" in instruction
    assert "real credentials" in instruction


@pytest.mark.asyncio
async def test_generate_attack_supports_vertex_and_configured_default_model(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clear_credentials(monkeypatch)
    monkeypatch.setenv("GOOGLE_GENAI_USE_VERTEXAI", "true")
    monkeypatch.setenv("GOOGLE_CLOUD_PROJECT", "test-project")
    monkeypatch.setenv("GOOGLE_CLOUD_LOCATION", "test-location")
    monkeypatch.setenv("SENTINEL_EXPERT_MODEL", "configured-expert")
    client_calls, models = install_fake_google(
        monkeypatch, SimpleNamespace(text="Vertex synthetic prompt")
    )

    assert await generate_attack("policy bypass") == "Vertex synthetic prompt"
    assert client_calls == [
        {
            "vertexai": True,
            "project": "test-project",
            "location": "test-location",
        }
    ]
    assert models.calls[0]["model"] == "configured-expert"


@pytest.mark.asyncio
async def test_generate_attack_rejects_invalid_style_before_provider_use(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clear_credentials(monkeypatch)
    monkeypatch.setitem(sys.modules, "google", None)

    with pytest.raises(ValueError, match="unsupported style"):
        await generate_attack("test", "not-supported")
    assert "standard" in SUPPORTED_STYLES


@pytest.mark.asyncio
async def test_generate_attack_requires_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clear_credentials(monkeypatch)
    client_calls, _ = install_fake_google(monkeypatch, SimpleNamespace(text="must not be returned"))

    with pytest.raises(ProviderError, match="set GOOGLE_API_KEY"):
        await generate_attack("test")
    assert client_calls == []


@pytest.mark.asyncio
async def test_generate_attack_requires_complete_vertex_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clear_credentials(monkeypatch)
    monkeypatch.setenv("GOOGLE_GENAI_USE_VERTEXAI", "true")
    monkeypatch.setenv("GOOGLE_CLOUD_PROJECT", "project-only")
    client_calls, _ = install_fake_google(monkeypatch, SimpleNamespace(text="unused"))

    with pytest.raises(ProviderError, match="requires GOOGLE_CLOUD_PROJECT"):
        await generate_attack("test")
    assert client_calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("text", [None, ""])
async def test_generate_attack_rejects_empty_provider_response(
    monkeypatch: pytest.MonkeyPatch, text: str | None
) -> None:
    clear_credentials(monkeypatch)
    monkeypatch.setenv("GOOGLE_API_KEY", "google-test-key")
    install_fake_google(monkeypatch, SimpleNamespace(text=text))

    with pytest.raises(ProviderError, match="returned no adversarial test text"):
        await generate_attack("test")


@pytest.mark.asyncio
async def test_generate_attack_reports_missing_optional_dependency(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clear_credentials(monkeypatch)
    monkeypatch.setitem(sys.modules, "google", None)
    monkeypatch.setitem(sys.modules, "google.genai", None)

    with pytest.raises(ProviderError, match=r"sentinel-oss-mcp\[gemini\]"):
        await generate_attack("test")
