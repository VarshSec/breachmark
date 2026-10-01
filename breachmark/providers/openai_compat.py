"""OpenAI and any OpenAI-compatible server (LM Studio, vLLM, OpenRouter, Together, llama.cpp, ...)."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from .base import GenResult, Provider, ProviderError


class OpenAICompatProvider(Provider):
    name = "openai"
    label = "OpenAI-compatible"
    needs_key = True
    default_concurrency = 4

    def _headers(self) -> Dict[str, str]:
        if not self.api_key:
            if "api.openai.com" in self.base_url:
                raise ProviderError("No API key found. Set OPENAI_API_KEY in your environment or .env file, "
                                    "or enter a key on the Settings page.")
            return {}
        return {"Authorization": f"Bearer {self.api_key}"}

    async def list_models(self) -> List[str]:
        try:
            data = await self._send("GET", f"{self.base_url}/models", headers=self._headers())
        except ProviderError as exc:
            if exc.status == 404:
                raise ProviderError(f"{exc} The base URL usually needs to end in /v1.", status=404)
            raise
        return sorted(m.get("id", "") for m in data.get("data", []) if m.get("id"))

    async def generate(self, prompt: str, model: str, temperature: float = 0.0, max_tokens: int = 4096,
                       options: Optional[Dict[str, Any]] = None) -> GenResult:
        headers = self._headers()
        body: Dict[str, Any] = {"model": model, "messages": [{"role": "user", "content": prompt}],
                                "temperature": temperature, "max_tokens": max_tokens}
        data: Dict[str, Any] = {}
        for _ in range(3):
            try:
                data = await self._send("POST", f"{self.base_url}/chat/completions", headers=headers, json=body)
                break
            except ProviderError as exc:
                text = str(exc).lower()
                # Newer models reject max_tokens / non-default temperature. Adapt once and retry.
                if exc.status == 400 and "max_completion_tokens" in text and "max_tokens" in body:
                    body["max_completion_tokens"] = body.pop("max_tokens")
                    continue
                if exc.status == 400 and "temperature" in text and "temperature" in body:
                    body.pop("temperature")
                    continue
                if exc.status == 404:
                    raise ProviderError(f"{exc} Check the model name and that the base URL ends in /v1.", status=404)
                raise
        choices = data.get("choices") or []
        if not choices:
            raise ProviderError("The server returned no choices.", retryable=True)
        content = (choices[0].get("message") or {}).get("content")
        if isinstance(content, list):
            content = "".join(part.get("text", "") for part in content if isinstance(part, dict))
        usage = data.get("usage") or {}
        return GenResult(text=content or "", prompt_tokens=usage.get("prompt_tokens"),
                         completion_tokens=usage.get("completion_tokens"))
