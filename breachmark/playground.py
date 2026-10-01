"""Run one piece of code (pasted by the user) through one model and one or more strategies."""
from __future__ import annotations

import asyncio
import re
import time
from typing import Any, Callable, Dict, List, Optional

import httpx

from .db import Database
from .parsing import AMBIGUOUS, parse_verdict
from .prompts import apply_input_policy, render_prompt
from .providers import ProviderError
from .runner import RunControl, RunManager
from .runs import _resolve_prompts, _validate_spec, normalize_options

MAX_CODE_CHARS = 600_000
COMMIT_URL = re.compile(r"^https://github\.com/[\w.\-]+/[\w.\-]+/commit/[0-9a-fA-F]{7,40}/?$")
VERDICT_TEXT = {1: "YES", 0: "NO", 2: "AMBIGUOUS"}


def clean_cwe(value: Optional[str]) -> Optional[str]:
    value = re.sub(r"\s+", " ", (value or "").strip())[:60]
    if not value:
        return None
    if value.isdigit():
        return f"CWE-{value}"
    return value


async def run_playground(db: Database, manager: RunManager, spec: Dict[str, Any]) -> Dict[str, Any]:
    code = spec.get("code") or ""
    if not code.strip():
        raise ValueError("Paste some code or a diff first.")
    if len(code) > MAX_CODE_CHARS:
        raise ValueError(f"The input is too large ({len(code)} characters; the limit is {MAX_CODE_CHARS}).")
    provider_name, model, _ = _validate_spec({**spec, "variants": ["vuln"]})
    opts = normalize_options(provider_name, spec.get("options"))
    opts["max_retries"] = min(opts["max_retries"], 1)
    prompts = _resolve_prompts(db, spec)
    cwe = clean_cwe(spec.get("cwe"))
    code_in, truncated, _ = apply_input_policy(code.replace("\r\n", "\n"), opts["max_input_chars"],
                                               "truncate" if opts["input_policy"] == "skip" else opts["input_policy"])
    provider = manager.provider_factory(provider_name, base_url=opts.get("base_url"), timeout=float(opts["timeout"]))

    async def one(p: Any) -> Dict[str, Any]:
        tpl = db.q1("SELECT template, key, version FROM prompts WHERE id=?", (p["id"],))
        label = tpl["key"] if tpl["version"] == 1 else f"{tpl['key']}@v{tpl['version']}"
        prompt = render_prompt(tpl["template"], code_in, cwe)
        started = time.perf_counter()
        try:
            gen = await manager._call(provider, model, prompt, opts, RunControl())
        except ProviderError as exc:
            return {"strategy": label, "error": str(exc), "verdict": None}
        verdict, method = parse_verdict(gen.text, allow_bare="one word" in tpl["template"].lower())
        return {"strategy": label, "verdict": verdict, "verdict_text": VERDICT_TEXT[verdict], "method": method,
                "response": gen.text, "latency_ms": int((time.perf_counter() - started) * 1000),
                "prompt_tokens": gen.prompt_tokens, "completion_tokens": gen.completion_tokens, "error": None}

    try:
        results = await asyncio.gather(*[one(p) for p in prompts])
    finally:
        await provider.aclose()
    votes = [r["verdict"] for r in results if r["verdict"] is not None]
    return {"results": results, "truncated": truncated, "cwe": cwe or "any security vulnerability",
            "summary": {"yes": votes.count(1), "no": votes.count(0), "ambiguous": votes.count(AMBIGUOUS),
                        "errors": sum(1 for r in results if r["verdict"] is None)}}


async def fetch_commit_diff(url: str, client: Optional[httpx.AsyncClient] = None) -> str:
    url = (url or "").strip()
    if not COMMIT_URL.match(url):
        raise ValueError("Enter a GitHub commit URL like https://github.com/owner/repo/commit/<sha>.")
    own = client is None
    client = client or httpx.AsyncClient(timeout=20.0, follow_redirects=True)
    try:
        resp = await client.get(url.rstrip("/") + ".diff")
    except httpx.HTTPError as exc:
        raise ValueError(f"Could not reach GitHub: {exc}")
    finally:
        if own:
            await client.aclose()
    if resp.status_code == 404:
        raise ValueError("GitHub returned 404. Check the URL (private repositories are not supported).")
    if resp.status_code >= 400:
        raise ValueError(f"GitHub returned HTTP {resp.status_code}.")
    text = resp.text
    if len(text) > MAX_CODE_CHARS:
        text = text[:MAX_CODE_CHARS] + "\n... (diff truncated)\n"
    return text
