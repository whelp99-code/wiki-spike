"""OpenAICompatClient (router) — parsing + error classification via mocked HTTP."""
import io
import json
import urllib.error

import pytest

from wiki_spike.llm import LLMError, OpenAICompatClient
from wiki_spike.runtime import FatalLLMError, TransientLLMError


def _fake_response(obj):
    class R:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self): return json.dumps(obj).encode()
    return R()


def _openai_payload(content_obj, prompt=11, completion=7):
    return {
        "choices": [{"message": {"content": json.dumps(content_obj)}}],
        "usage": {"prompt_tokens": prompt, "completion_tokens": completion},
    }


def test_router_parses_json_and_usage(monkeypatch):
    client = OpenAICompatClient(base_url="http://localhost:20128/v1", api_key="k")
    payload = _openai_payload({"claims": [], "abstain": True})
    monkeypatch.setattr("urllib.request.urlopen", lambda *a, **k: _fake_response(payload))
    out = client.complete_json("m", "sys", "user")
    assert out == {"claims": [], "abstain": True}
    assert client.last_usage == {"input_tokens": 11, "output_tokens": 7}


def test_router_gated_without_base_url():
    with pytest.raises(LLMError):
        OpenAICompatClient(base_url="", api_key="k").complete_json("m", "s", "u")


def test_router_gated_without_model_id():
    with pytest.raises(LLMError):
        OpenAICompatClient(base_url="http://x/v1").complete_json("", "s", "u")


def test_router_503_is_transient(monkeypatch):
    def boom(*a, **k):
        raise urllib.error.HTTPError("u", 503, "err", {}, io.BytesIO(b""))
    monkeypatch.setattr("urllib.request.urlopen", boom)
    with pytest.raises(TransientLLMError):
        OpenAICompatClient(base_url="http://x/v1").complete_json("m", "s", "u")


def test_router_400_is_fatal(monkeypatch):
    def boom(*a, **k):
        raise urllib.error.HTTPError("u", 400, "bad", {}, io.BytesIO(b""))
    monkeypatch.setattr("urllib.request.urlopen", boom)
    with pytest.raises(FatalLLMError):
        OpenAICompatClient(base_url="http://x/v1").complete_json("m", "s", "u")


def test_router_bad_json_is_fatal(monkeypatch):
    payload = {"choices": [{"message": {"content": "not json"}}], "usage": {}}
    monkeypatch.setattr("urllib.request.urlopen", lambda *a, **k: _fake_response(payload))
    with pytest.raises(FatalLLMError):
        OpenAICompatClient(base_url="http://x/v1").complete_json("m", "s", "u")
