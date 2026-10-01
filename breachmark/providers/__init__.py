"""Provider registry."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

import httpx

from .. import config
from .anthropic import AnthropicProvider
from .base import GenResult, Provider, ProviderError
from .mock import MockProvider
from .ollama import OllamaProvider
from .openai_compat import OpenAICompatProvider

PROVIDER_CLASSES = {
    "ollama": OllamaProvider,
    "openai": OpenAICompatProvider,
    "anthropic": AnthropicProvider,
    "mock": MockProvider,
}

__all__ = ["GenResult", "Provider", "ProviderError", "PROVIDER_CLASSES", "make_provider", "default_base_url",
           "provider_info"]


def default_base_url(name: str) -> str:
    settings = config.get_settings()
    return {"ollama": settings.ollama_host, "openai": settings.openai_base_url,
            "anthropic": settings.anthropic_base_url, "mock": ""}.get(name, "")


def make_provider(name: str, base_url: Optional[str] = None, timeout: float = 300.0,
                  client: Optional[httpx.AsyncClient] = None) -> Provider:
    if name not in PROVIDER_CLASSES:
        raise ValueError(f"Unknown provider '{name}'. Choose one of: {', '.join(PROVIDER_CLASSES)}")
    cls = PROVIDER_CLASSES[name]
    return cls(base_url=base_url or default_base_url(name), api_key=config.get_api_key(name),
               timeout=timeout, client=client)


def provider_info() -> List[Dict[str, Any]]:
    out = []
    for name, cls in PROVIDER_CLASSES.items():
        out.append({
            "name": name, "label": cls.label, "needs_key": cls.needs_key,
            "default_concurrency": cls.default_concurrency, "default_base_url": default_base_url(name),
            "key_source": config.key_source(name) if cls.needs_key else "not needed",
        })
    return out
