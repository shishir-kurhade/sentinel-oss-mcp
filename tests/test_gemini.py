from __future__ import annotations

import asyncio
import json
import sys
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

from sentinel_oss.contracts import (
    EvaluationStage,
    ExchangeRequest,
    Outcome,
    ProviderVerdict,
    SourceKind,
    TrustLevel,
)
from sentinel_oss.providers import ProviderError
from sentinel_oss.providers.gemini import GeminiClassifier, GeminiEmbedder


class FakeGenerateContentConfig:
    def __init__(self, **kwargs: object) -> None:
        self.values = kwargs


class ScriptedModels:
    def __init__(
        self,
        *,
        generated: list[object] | None = None,
        embedded: list[object] | None = None,
    ) -> None:
        self.generated = list(generated or [])
        self.embedded = list(embedded or [])
        self.generate_calls: list[dict[str, object]] = []
        self.embed_calls: list[dict[str, object]] = []

    async def generate_content(self, **kwargs: object) -> object:
        self.generate_calls.append(kwargs)
        response = self.generated.pop(0)
        if isinstance(response, Exception):
            raise response
        if callable(response):
            return await response()
        return response

    async def embed_content(self, **kwargs: object) -> object:
        self.embed_calls.append(kwargs)
        response = self.embedded.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def install_fake_google(
    monkeypatch: pytest.MonkeyPatch,
    *,
    client_factory: Any | None = None,
) -> ModuleType:
    google = ModuleType("google")
    google.__path__ = []  # type: ignore[attr-defined]
    genai = ModuleType("google.genai")
    genai.__path__ = []  # type: ignore[attr-defined]
    types_module = ModuleType("google.genai.types")
    types_module.GenerateContentConfig = FakeGenerateContentConfig  # type: ignore[attr-defined]
    genai.types = types_module  # type: ignore[attr-defined]
    if client_factory is not None:
        genai.Client = client_factory  # type: ignore[attr-defined]
    google.genai = genai  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "google", google)
    monkeypatch.setitem(sys.modules, "google.genai", genai)
    monkeypatch.setitem(sys.modules, "google.genai.types", types_module)
    return genai


def exchange() -> ExchangeRequest:
    return ExchangeRequest(
        policy_id="banking",
        trusted_user_intent="Answer the user's support request.",
        content="Untrusted tool output.",
        source_kind=SourceKind.TOOL,
        trust_level=TrustLevel.UNTRUSTED,
        draft_output="A draft response.",
    )


def verdict() -> ProviderVerdict:
    return ProviderVerdict(
        outcome=Outcome.ALLOW,
        reason_code="SAFE_TEST",
        message="The synthetic exchange is allowed.",
        confidence=0.97,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("parsed", ["model", "mapping", "json"])
async def test_classifier_accepts_each_supported_structured_response_shape(
    monkeypatch: pytest.MonkeyPatch, parsed: str
) -> None:
    install_fake_google(monkeypatch)
    expected = verdict()
    if parsed == "model":
        response = SimpleNamespace(parsed=expected)
    elif parsed == "mapping":
        response = SimpleNamespace(parsed=expected.model_dump(mode="json"))
    else:
        response = SimpleNamespace(text=expected.model_dump_json())
    models = ScriptedModels(generated=[response])
    client = SimpleNamespace(aio=SimpleNamespace(models=models))
    classifier = GeminiClassifier("gemini-test", client=client)

    result = await classifier.classify(
        exchange(),
        policy_instructions="Apply TEST-001.",
        stage=EvaluationStage.LIGHTWEIGHT_CLASSIFIER,
    )

    assert result == expected
    assert classifier.model_id == "gemini-test"
    call = models.generate_calls[0]
    assert call["model"] == "gemini-test"
    payload = json.loads(str(call["contents"]))
    assert payload == {
        "evaluation_stage": "LIGHTWEIGHT_CLASSIFIER",
        "trusted_user_intent": "Answer the user's support request.",
        "content_source": "TOOL",
        "content_trust": "UNTRUSTED",
        "content": "Untrusted tool output.",
        "draft_output": "A draft response.",
    }
    config = call["config"]
    assert isinstance(config, FakeGenerateContentConfig)
    assert config.values["temperature"] == 0.0
    assert config.values["response_mime_type"] == "application/json"
    assert config.values["response_schema"] is ProviderVerdict
    assert "Apply TEST-001" in str(config.values["system_instruction"])


@pytest.mark.asyncio
async def test_classifier_retries_malformed_output_then_succeeds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_fake_google(monkeypatch)
    models = ScriptedModels(
        generated=[SimpleNamespace(text="not-json"), SimpleNamespace(parsed=verdict())]
    )
    classifier = GeminiClassifier(
        "gemini-test",
        client=SimpleNamespace(aio=SimpleNamespace(models=models)),
        max_retries=1,
    )

    result = await classifier.classify(
        exchange(),
        policy_instructions="Test policy",
        stage=EvaluationStage.EXPERT_CLASSIFIER,
    )

    assert result == verdict()
    assert len(models.generate_calls) == 2


@pytest.mark.asyncio
async def test_classifier_contains_timeout_after_bounded_retries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_fake_google(monkeypatch)

    async def slow() -> object:
        await asyncio.sleep(0.05)
        return SimpleNamespace(parsed=verdict())

    models = ScriptedModels(generated=[slow, slow])
    classifier = GeminiClassifier(
        "gemini-test",
        client=SimpleNamespace(aio=SimpleNamespace(models=models)),
        timeout_seconds=0.001,
        max_retries=1,
    )

    with pytest.raises(ProviderError, match="failed after bounded retries"):
        await classifier.classify(
            exchange(),
            policy_instructions="Test policy",
            stage=EvaluationStage.EXPERT_CLASSIFIER,
        )
    assert len(models.generate_calls) == 2


@pytest.mark.asyncio
async def test_embedder_returns_plain_vector_and_contains_provider_errors() -> None:
    success_models = ScriptedModels(
        embedded=[SimpleNamespace(embeddings=[SimpleNamespace(values=(0.1, 0.2))])]
    )
    embedder = GeminiEmbedder(
        "embed-test",
        client=SimpleNamespace(aio=SimpleNamespace(models=success_models)),
    )

    assert await embedder.embed("hello") == [0.1, 0.2]
    assert embedder.model_id == "embed-test"
    assert success_models.embed_calls == [{"model": "embed-test", "contents": "hello"}]

    failed_models = ScriptedModels(embedded=[RuntimeError("offline")])
    failed = GeminiEmbedder(client=SimpleNamespace(aio=SimpleNamespace(models=failed_models)))
    with pytest.raises(ProviderError, match="Gemini embedding failed: offline"):
        await failed.embed("hello")


def test_client_construction_supports_developer_api_and_vertex(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []

    def client_factory(**kwargs: object) -> object:
        calls.append(kwargs)
        return SimpleNamespace(aio=SimpleNamespace(models=object()))

    install_fake_google(monkeypatch, client_factory=client_factory)

    GeminiClassifier("one", api_key="test-key")
    GeminiEmbedder("two", use_vertex=True, project="project", location="location")

    assert calls == [
        {"api_key": "test-key"},
        {"vertexai": True, "project": "project", "location": "location"},
    ]


def test_client_construction_rejects_missing_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_fake_google(monkeypatch, client_factory=lambda **kwargs: kwargs)

    with pytest.raises(ProviderError, match="requires an API key"):
        GeminiClassifier("test")
    with pytest.raises(ProviderError, match="requires project and location"):
        GeminiEmbedder(use_vertex=True, project="project")
