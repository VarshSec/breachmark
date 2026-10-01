"""Ollama (local models) via the native /api/chat endpoint."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from .base import GenResult, Provider, ProviderError


class OllamaProvider(Provider):
    name = "ollama"
    label = "Ollama (local)"
    default_concurrency = 1

    async def list_models(self) -> List[str]:
        data = await self._send("GET", f"{self.base_url}/api/tags")
        return sorted(m.get("name", "") for m in data.get("models", []) if m.get("name"))

    async def generate(self, prompt: str, model: str, temperature: float = 0.0, max_tokens: int = 4096,
                       options: Optional[Dict[str, Any]] = None) -> GenResult:
        options = options or {}
        opts: Dict[str, Any] = {"temperature": temperature, "num_predict": max_tokens}
        if options.get("num_ctx"):
            opts["num_ctx"] = int(options["num_ctx"])
        body = {"model": model, "messages": [{"role": "user", "content": prompt}], "stream": False, "options": opts}
        try:
            data = await self._send("POST", f"{self.base_url}/api/chat", json=body)
        except ProviderError as exc:
            if exc.status == 404:
                raise ProviderError(f"Model '{model}' was not found on the Ollama server. "
                                    f"Install it with: ollama pull {model}", status=404)
            raise
        message = data.get("message") or {}
        text = message.get("content") or ""
        if not text and message.get("thinking"):
            text = "<think>" + message["thinking"]  # unterminated on purpose: no answer was produced
        if not text and not data.get("done"):
            raise ProviderError("Ollama returned an empty response.", retryable=True)
        return GenResult(text=text, prompt_tokens=data.get("prompt_eval_count"), completion_tokens=data.get("eval_count"))
