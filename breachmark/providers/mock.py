"""Synthetic provider for demos and tests. Produces deterministic, clearly fake answers.

It is NOT a real model: results from it only prove the pipeline works. The UI marks mock runs.
"""
from __future__ import annotations

import asyncio
import hashlib
import re
from typing import Any, Dict, List, Optional

from .base import GenResult, Provider, ProviderError

PERSONAS = {
    "mock-balanced": 0.5,
    "mock-eager": 0.8,
    "mock-cautious": 0.25,
    "mock-always-yes": 1.0,
    "mock-always-no": 0.0,
    "mock-garbled": 0.5,   # never states a verdict
    "mock-flaky": 0.5,     # fails the first attempt on ~30% of prompts, then succeeds
    "mock-broken": 0.5,    # always fails with a non-retryable error
}
_RISKY = re.compile(r"\b(strcpy|strcat|sprintf|memcpy|memmove|malloc|free|kmalloc|kfree|copy_from_user|alloca)\b")


class MockProvider(Provider):
    name = "mock"
    label = "Mock (synthetic)"
    default_concurrency = 4
    latency = 0.01

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self._seen: Dict[str, int] = {}

    async def list_models(self) -> List[str]:
        return list(PERSONAS)

    async def generate(self, prompt: str, model: str, temperature: float = 0.0, max_tokens: int = 4096,
                       options: Optional[Dict[str, Any]] = None) -> GenResult:
        digest = int(hashlib.sha256((model + "\0" + prompt).encode("utf-8", "replace")).hexdigest(), 16)
        if self.latency:
            await asyncio.sleep(self.latency)
        if model == "mock-broken":
            raise ProviderError("Mock model is configured to fail (HTTP 400).", status=400)
        if model == "mock-flaky":
            key = str(digest)
            self._seen[key] = self._seen.get(key, 0) + 1
            if digest % 10 < 3 and self._seen[key] == 1:
                raise ProviderError("Mock transient failure (HTTP 503).", retryable=True, status=503)
        base = PERSONAS.get(model, 0.5)
        risky = len(_RISKY.findall(prompt))
        p_yes = base if base in (0.0, 1.0) else min(0.95, base + min(risky, 20) * 0.01)
        says_yes = ((digest >> 8) % 10_000) / 10_000 < p_yes
        verdict = "YES" if says_yes else "NO"
        if "Answer with exactly one word" in prompt:
            text = verdict
        elif model == "mock-garbled":
            text = "<thinking>The code is complex and it is hard to say either way.</thinking>\nI cannot decide."
        else:
            reason = ("a memory operation without an obvious bound check" if says_yes
                      else "bounds and lifetimes appear to be handled correctly")
            text = (f"<thinking>\nMock analysis: {reason}. This text is synthetic.\n</thinking>\n"
                    f"<assessment>\nMock conclusion: {verdict}. Severity: {'High' if says_yes else 'Low'}.\n</assessment>\n"
                    f"VERDICT: {verdict}")
        return GenResult(text=text, prompt_tokens=len(prompt) // 4, completion_tokens=len(text) // 4)
