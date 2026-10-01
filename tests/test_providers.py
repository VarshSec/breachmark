import asyncio
import json

import httpx
import pytest

from breachmark.providers import ProviderError
from breachmark.providers.anthropic import AnthropicProvider
from breachmark.providers.ollama import OllamaProvider
from breachmark.providers.openai_compat import OpenAICompatProvider


def client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def test_ollama_chat_and_model_missing():
    def handler(req):
        if req.url.path == "/api/tags":
            return httpx.Response(200, json={"models": [{"name": "b"}, {"name": "a"}]})
        body = json.loads(req.content)
        assert body["stream"] is False and body["options"]["num_ctx"] == 4096
        if body["model"] == "nope":
            return httpx.Response(404, json={"error": "model 'nope' not found"})
        return httpx.Response(200, json={"message": {"content": "VERDICT: YES"}, "done": True,
                                         "prompt_eval_count": 7, "eval_count": 3})

    async def go():
        p = OllamaProvider("http://h:11434", client=client(handler))
        assert await p.list_models() == ["a", "b"]
        r = await p.generate("hi", "m", 0.0, 50, {"num_ctx": 4096})
        assert (r.text, r.prompt_tokens, r.completion_tokens) == ("VERDICT: YES", 7, 3)
        with pytest.raises(ProviderError, match="ollama pull nope"):
            await p.generate("hi", "nope", 0.0, 50, {"num_ctx": 4096})
    asyncio.run(go())


def test_openai_adapts_to_newer_models_and_requires_key():
    seen = []

    def handler(req):
        body = json.loads(req.content)
        seen.append(sorted(body))
        assert req.headers["authorization"] == "Bearer k"
        if "max_tokens" in body:
            return httpx.Response(400, json={"error": {"message": "Use 'max_completion_tokens' instead of max_tokens"}})
        if "temperature" in body:
            return httpx.Response(400, json={"error": {"message": "temperature does not support 0.0"}})
        return httpx.Response(200, json={"choices": [{"message": {"content": "NO"}}],
                                         "usage": {"prompt_tokens": 2, "completion_tokens": 1}})

    async def go():
        p = OpenAICompatProvider("https://api.openai.com/v1", "k", client=client(handler))
        r = await p.generate("hi", "gpt")
        assert r.text == "NO" and len(seen) == 3 and "max_completion_tokens" in seen[-1] and "temperature" not in seen[-1]
        with pytest.raises(ProviderError, match="No API key"):
            await OpenAICompatProvider("https://api.openai.com/v1", None).generate("hi", "gpt")
    asyncio.run(go())


def test_anthropic_messages():
    def handler(req):
        assert req.headers["x-api-key"] == "k" and req.headers["anthropic-version"]
        if req.url.path == "/v1/models":
            return httpx.Response(200, json={"data": [{"id": "claude-x"}]})
        return httpx.Response(200, json={"content": [{"type": "text", "text": "VERDICT: NO"}],
                                         "usage": {"input_tokens": 4, "output_tokens": 2}, "stop_reason": "end_turn"})

    async def go():
        p = AnthropicProvider("https://api.anthropic.com", "k", client=client(handler))
        assert await p.list_models() == ["claude-x"]
        r = await p.generate("hi", "claude-x")
        assert (r.text, r.prompt_tokens, r.completion_tokens) == ("VERDICT: NO", 4, 2)
    asyncio.run(go())


@pytest.mark.parametrize("status,retryable", [(401, False), (403, False), (400, False), (404, False),
                                               (429, True), (500, True), (503, True)])
def test_http_error_classification(status, retryable):
    def handler(req):
        return httpx.Response(status, json={"error": {"message": "boom"}}, headers={"retry-after": "3"})

    async def go():
        p = OllamaProvider("http://h", client=client(handler))
        with pytest.raises(ProviderError) as exc:
            await p._send("GET", "http://h/x")
        assert exc.value.retryable is retryable and exc.value.status == status
        if status == 429:
            assert exc.value.retry_after == 3.0
    asyncio.run(go())


def test_connection_refused_is_retryable_and_explained():
    async def go():
        p = OllamaProvider("http://127.0.0.1:9", timeout=2)
        result = await p.ping()
        assert not result["ok"] and "Cannot connect" in result["message"]
        await p.aclose()
    asyncio.run(go())
