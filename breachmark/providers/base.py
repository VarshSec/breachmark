"""Provider interface shared by every model backend."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import httpx


class ProviderError(Exception):
    """A model call failed. `retryable` tells the runner whether trying again can help."""

    def __init__(self, message: str, retryable: bool = False, status: Optional[int] = None,
                 retry_after: Optional[float] = None):
        super().__init__(message)
        self.retryable = retryable
        self.status = status
        self.retry_after = retry_after


@dataclass
class GenResult:
    text: str
    prompt_tokens: Optional[int] = None
    completion_tokens: Optional[int] = None


def _error_message(resp: httpx.Response) -> str:
    try:
        data = resp.json()
    except ValueError:
        return resp.text.strip()[:300] or f"HTTP {resp.status_code}"
    err = data.get("error", data) if isinstance(data, dict) else data
    if isinstance(err, dict):
        return str(err.get("message") or err.get("detail") or err)[:300]
    return str(err)[:300]


class Provider:
    name = ""
    label = ""
    needs_key = False
    default_concurrency = 1

    def __init__(self, base_url: Optional[str] = None, api_key: Optional[str] = None,
                 timeout: float = 300.0, client: Optional[httpx.AsyncClient] = None):
        self.base_url = (base_url or "").rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self._client = client
        self._owns_client = client is None

    def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=httpx.Timeout(self.timeout, connect=10.0))
        return self._client

    async def aclose(self) -> None:
        if self._client is not None and self._owns_client:
            await self._client.aclose()
            self._client = None

    async def _send(self, method: str, url: str, *, headers: Optional[Dict[str, str]] = None,
                    json: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        try:
            resp = await self._http().request(method, url, headers=headers, json=json, params=params)
        except httpx.ConnectError:
            raise ProviderError(f"Cannot connect to {self.base_url}. Is the server running and the URL correct?",
                                retryable=True)
        except httpx.TimeoutException:
            raise ProviderError(f"The request timed out after {self.timeout:.0f}s.", retryable=True)
        except httpx.HTTPError as exc:
            raise ProviderError(f"Network error: {exc}", retryable=True)
        if resp.status_code >= 400:
            raise self._http_error(resp)
        try:
            data = resp.json()
        except ValueError:
            raise ProviderError("The server returned a response that is not JSON. Check the base URL.", retryable=False)
        if not isinstance(data, dict):
            raise ProviderError("Unexpected response format from the server.", retryable=False)
        return data

    @staticmethod
    def _http_error(resp: httpx.Response) -> ProviderError:
        message = _error_message(resp)
        status = resp.status_code
        if status in (401, 403):
            return ProviderError(f"Authentication failed (HTTP {status}). Check the API key. {message}", status=status)
        if status == 429 or status == 408 or status >= 500:
            retry_after = None
            try:
                retry_after = float(resp.headers.get("retry-after", ""))
            except ValueError:
                pass
            return ProviderError(f"HTTP {status}: {message}", retryable=True, status=status, retry_after=retry_after)
        return ProviderError(f"HTTP {status}: {message}", status=status)

    async def generate(self, prompt: str, model: str, temperature: float = 0.0, max_tokens: int = 4096,
                       options: Optional[Dict[str, Any]] = None) -> GenResult:
        raise NotImplementedError

    async def list_models(self) -> List[str]:
        raise NotImplementedError

    async def ping(self) -> Dict[str, Any]:
        try:
            models = await self.list_models()
        except ProviderError as exc:
            return {"ok": False, "message": str(exc), "models": []}
        return {"ok": True, "message": f"Connected. {len(models)} model(s) available.", "models": models}
