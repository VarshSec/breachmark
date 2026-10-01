"""Anthropic Messages API."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from .base import GenResult, Provider, ProviderError

API_VERSION = "2023-06-01"


class AnthropicProvider(Provider):
    name = "anthropic"
    label = "Anthropic"
    needs_key = True
    default_concurrency = 4

    def _headers(self) -> Dict[str, str]:
        if not self.api_key:
            raise ProviderError("No API key found. Set ANTHROPIC_API_KEY in your environment or .env file, "
                                "or enter a key on the Settings page.")
        return {"x-api-key": self.api_key, "anthropic-version": API_VERSION, "content-type": "application/json"}

    async def list_models(self) -> List[str]:
        data = await self._send("GET", f"{self.base_url}/v1/models", headers=self._headers(), params={"limit": 100})
        return [m.get("id", "") for m in data.get("data", []) if m.get("id")]

    async def generate(self, prompt: str, model: str, temperature: float = 0.0, max_tokens: int = 4096,
                       options: Optional[Dict[str, Any]] = None) -> GenResult:
        headers = self._headers()
        body: Dict[str, Any] = {"model": model, "max_tokens": max_tokens, "temperature": temperature,
                                "messages": [{"role": "user", "content": prompt}]}
        data: Dict[str, Any] = {}
        for _ in range(2):
            try:
                data = await self._send("POST", f"{self.base_url}/v1/messages", headers=headers, json=body)
                break
            except ProviderError as exc:
                if exc.status == 400 and "temperature" in str(exc).lower() and "temperature" in body:
                    body.pop("temperature")  # some models do not accept a temperature
                    continue
                if exc.status == 404:
                    raise ProviderError(f"{exc} Check the model name.", status=404)
                raise
        blocks = data.get("content") or []
        text = "".join(b.get("text", "") for b in blocks if isinstance(b, dict) and b.get("type") == "text")
        usage = data.get("usage") or {}
        if not text and not blocks and data.get("stop_reason") is None:
            raise ProviderError("The API returned an empty response.", retryable=True)
        return GenResult(text=text, prompt_tokens=usage.get("input_tokens"), completion_tokens=usage.get("output_tokens"))
