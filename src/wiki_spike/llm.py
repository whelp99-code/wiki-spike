"""LLM client interface (P0 first slice, v3.3 §5, §16).

Both the deterministic test path and the real Anthropic path implement LLMClient, so
tests stay deterministic (MockLLMClient) while the real path (AnthropicClient) is
exercised only when an API key + an EXACT model id are supplied.

Exact model ids are still PENDING (a selection eval must fix extraction/verification/
render ids). Nothing here hardcodes a production model id.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Protocol


class LLMError(RuntimeError):
    pass


@dataclass
class LLMConfig:
    # PENDING: fill via selection eval. Kept empty so the real path refuses to run
    # against an unspecified model.
    extraction_model_id: str = ""
    verification_model_id: str = ""
    render_model_id: str = ""
    max_tokens: int = 1024
    temperature: float = 0.0  # reduces variance; NOT determinism (see docs)


class LLMClient(Protocol):
    def complete_json(self, model_id: str, system: str, user: str) -> dict: ...


class MockLLMClient:
    """Deterministic client driven by a fixed table of (system,user)->response.

    Used in tests and golden eval so the pipeline is exercised without a live model.
    Optional: `usage` reports token accounting; `fail_times`/`fail_error` scripts a
    number of transient failures before succeeding (for retry tests).
    """

    def __init__(
        self,
        responses: dict[str, dict] | None = None,
        usage: dict | None = None,
        fail_times: int = 0,
        fail_error: Exception | None = None,
    ) -> None:
        self._responses = responses or {}
        self.last_usage = usage or {"input_tokens": 0, "output_tokens": 0}
        self._fail_times = fail_times
        self._fail_error = fail_error
        self.calls = 0

    def register(self, key: str, response: dict) -> None:
        self._responses[key] = response

    def complete_json(self, model_id: str, system: str, user: str) -> dict:
        self.calls += 1
        if self._fail_times > 0:
            self._fail_times -= 1
            raise self._fail_error or RuntimeError("scripted failure")
        for k, v in self._responses.items():
            if k in user:
                return v
        return {"claims": [], "abstain": True}


class AnthropicClient:
    """Real client (gated). Calls the Messages API; requires ANTHROPIC_API_KEY.

    Not invoked by the test suite. Present so the pipeline can be wired end-to-end
    once an exact model id is locked.
    """

    ENDPOINT = "https://api.anthropic.com/v1/messages"

    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")

    def complete_json(self, model_id: str, system: str, user: str) -> dict:
        if not self.api_key:
            raise LLMError("ANTHROPIC_API_KEY not set; real LLM path is disabled")
        if not model_id:
            raise LLMError("exact model id is PENDING; refusing to call an unspecified model")
        import socket
        import urllib.error
        import urllib.request

        body = json.dumps({
            "model": model_id,
            "max_tokens": 1024,
            "temperature": 0.0,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }).encode("utf-8")
        req = urllib.request.Request(
            self.ENDPOINT, data=body, method="POST",
            headers={
                "content-type": "application/json",
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310
                payload = json.loads(resp.read())
        except urllib.error.HTTPError as e:
            from .runtime import FatalLLMError, TransientLLMError, classify_http
            cls = classify_http(e.code)
            if cls is TransientLLMError:
                raise TransientLLMError(f"Anthropic HTTP {e.code}") from e
            raise FatalLLMError(f"Anthropic HTTP {e.code}") from e
        except (urllib.error.URLError, TimeoutError, socket.timeout) as e:
            from .runtime import TransientLLMError
            raise TransientLLMError(f"Anthropic network error: {e}") from e
        usage = payload.get("usage") or {}
        self.last_usage = {
            "input_tokens": int(usage.get("input_tokens", 0)),
            "output_tokens": int(usage.get("output_tokens", 0)),
        }
        # Concatenate text blocks and parse strict JSON.
        text = "".join(b.get("text", "") for b in payload.get("content", []) if b.get("type") == "text")
        try:
            return json.loads(text)
        except json.JSONDecodeError as e:
            from .runtime import FatalLLMError
            raise FatalLLMError(f"model did not return valid JSON: {e}") from e


class OpenAICompatClient:
    """OpenAI-compatible chat client (gated) for a local router/gateway (e.g. 9router).

    Reads config from the environment ONLY (never from code/args-in-chat):
      ROUTER_BASE_URL   e.g. http://localhost:20128/v1
      ROUTER_API_KEY    bearer token (kept out of source; may be empty for local-only)
    Same return contract as the other clients: strict JSON object from the model's
    message content. Errors are classified like AnthropicClient (429/5xx/network ->
    transient; other 4xx / bad JSON -> fatal). last_usage is populated for cost.
    """

    def __init__(self, base_url: str | None = None, api_key: str | None = None) -> None:
        self.base_url = (base_url or os.environ.get("ROUTER_BASE_URL", "")).rstrip("/")
        self.api_key = api_key if api_key is not None else os.environ.get("ROUTER_API_KEY", "")
        self.last_usage = {"input_tokens": 0, "output_tokens": 0}

    def complete_json(self, model_id: str, system: str, user: str) -> dict:
        if not self.base_url:
            raise LLMError("ROUTER_BASE_URL not set; router path is disabled")
        if not model_id:
            raise LLMError("exact model id is PENDING; refusing to call an unspecified model")
        import socket
        import urllib.error
        import urllib.request

        body = json.dumps({
            "model": model_id,
            "temperature": 0.0,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "response_format": {"type": "json_object"},
        }).encode("utf-8")
        headers = {"content-type": "application/json"}
        if self.api_key:
            headers["authorization"] = f"Bearer {self.api_key}"
        req = urllib.request.Request(
            f"{self.base_url}/chat/completions", data=body, method="POST", headers=headers
        )
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:  # noqa: S310
                payload = json.loads(resp.read())
        except urllib.error.HTTPError as e:
            from .runtime import FatalLLMError, TransientLLMError, classify_http
            cls = classify_http(e.code)
            if cls is TransientLLMError:
                raise TransientLLMError(f"router HTTP {e.code}") from e
            raise FatalLLMError(f"router HTTP {e.code}") from e
        except (urllib.error.URLError, TimeoutError, socket.timeout) as e:
            from .runtime import TransientLLMError
            raise TransientLLMError(f"router network error: {e}") from e
        usage = payload.get("usage") or {}
        self.last_usage = {
            "input_tokens": int(usage.get("prompt_tokens", 0)),
            "output_tokens": int(usage.get("completion_tokens", 0)),
        }
        try:
            content = payload["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as e:
            from .runtime import FatalLLMError
            raise FatalLLMError(f"unexpected router response shape: {e}") from e
        try:
            return json.loads(content)
        except json.JSONDecodeError as e:
            from .runtime import FatalLLMError
            raise FatalLLMError(f"model did not return valid JSON: {e}") from e
