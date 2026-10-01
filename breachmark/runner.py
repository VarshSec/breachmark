"""Asynchronous run executor with pause, resume, cancel, retries and a fail-fast circuit breaker."""
from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from .db import Database, now_iso
from .parsing import AMBIGUOUS, JUDGE_PROMPT, parse_judge, parse_verdict
from .prompts import apply_input_policy, render_prompt
from .providers import GenResult, Provider, ProviderError, make_provider

log = logging.getLogger("breachmark.runner")

RETRY_BASE_DELAY = 1.5     # seconds; exponential backoff base (tests set this to 0)
ABORT_AFTER = 10           # consecutive failed tasks before a run is stopped as 'failed'


@dataclass
class RunControl:
    pause: bool = False
    cancel: bool = False
    abort_reason: Optional[str] = None
    consecutive_errors: int = 0
    workers: List["asyncio.Task[Any]"] = field(default_factory=list)

    @property
    def stopped(self) -> bool:
        return self.pause or self.cancel or self.abort_reason is not None


class RunManager:
    def __init__(self, db: Database, provider_factory: Callable[..., Provider] = make_provider):
        self.db = db
        self.provider_factory = provider_factory
        self._ctl: Dict[int, RunControl] = {}
        self._tasks: Dict[int, "asyncio.Task[None]"] = {}

    # ----- public control API -------------------------------------------------
    def is_active(self, run_id: int) -> bool:
        task = self._tasks.get(run_id)
        return task is not None and not task.done()

    def active_ids(self) -> List[int]:
        return [rid for rid in self._tasks if self.is_active(rid)]

    async def start(self, run_id: int) -> None:
        if self.is_active(run_id):
            return
        if self.db.q1("SELECT id FROM runs WHERE id=?", (run_id,)) is None:
            raise ValueError(f"Run {run_id} does not exist.")
        ctl = RunControl()
        self._ctl[run_id] = ctl
        self._tasks[run_id] = asyncio.create_task(self._execute(run_id, ctl))

    def pause(self, run_id: int) -> bool:
        ctl = self._ctl.get(run_id)
        if ctl and self.is_active(run_id):
            ctl.pause = True
            return True
        return False

    def cancel(self, run_id: int) -> bool:
        ctl = self._ctl.get(run_id)
        if ctl and self.is_active(run_id):
            ctl.cancel = True
            for worker in ctl.workers:
                worker.cancel()
            return True
        return False

    async def wait(self, run_id: int) -> None:
        task = self._tasks.get(run_id)
        if task:
            await asyncio.shield(task)

    async def shutdown(self) -> None:
        for run_id in self.active_ids():
            self.pause(run_id)
        tasks = [t for t in self._tasks.values() if not t.done()]
        if tasks:
            await asyncio.wait(tasks, timeout=15)

    def recover_interrupted(self) -> int:
        """Runs left 'running' by a crash or hard stop become 'paused' so they can be resumed."""
        with self.db.tx() as conn:
            return conn.execute("UPDATE runs SET status='paused', error='Interrupted when the app stopped.' "
                                "WHERE status='running'").rowcount

    # ----- execution ------------------------------------------------------------
    def _set_status(self, run_id: int, status: str, error: Optional[str] = None, finished: bool = False) -> None:
        self.db.x("UPDATE runs SET status=?, error=?, finished_at=? WHERE id=?",
                  (status, error, now_iso() if finished else None, run_id))

    async def _execute(self, run_id: int, ctl: RunControl) -> None:
        provider: Optional[Provider] = None
        try:
            run = self.db.q1("SELECT * FROM runs WHERE id=?", (run_id,))
            opts = json.loads(run["options"])
            provider = self.provider_factory(run["provider"], base_url=opts.get("base_url"),
                                             timeout=float(opts.get("timeout", 300)))
            self.db.x("UPDATE runs SET status='running', error=NULL, finished_at=NULL, "
                      "started_at=COALESCE(started_at, ?) WHERE id=?", (now_iso(), run_id))
            pending = [r["id"] for r in self.db.q(
                "SELECT id FROM results WHERE run_id=? AND status='pending' ORDER BY id", (run_id,))]
            queue: "asyncio.Queue[int]" = asyncio.Queue()
            for rid in pending:
                queue.put_nowait(rid)
            n_workers = max(1, min(int(opts.get("concurrency") or 1), len(pending) or 1))
            ctl.workers = [asyncio.create_task(self._worker(run, opts, provider, ctl, queue)) for _ in range(n_workers)]
            await asyncio.gather(*ctl.workers, return_exceptions=True)

            left = self.db.scalar("SELECT COUNT(*) FROM results WHERE run_id=? AND status='pending'", (run_id,))
            if ctl.cancel:
                self._set_status(run_id, "cancelled", finished=True)
            elif ctl.abort_reason:
                self._set_status(run_id, "failed", ctl.abort_reason, finished=True)
            elif ctl.pause and left:
                self._set_status(run_id, "paused")
            else:
                self._set_status(run_id, "completed", finished=True)
        except asyncio.CancelledError:
            self._set_status(run_id, "paused", "Interrupted when the app stopped.")
            raise
        except Exception as exc:  # setup failure: bad provider name, DB problem, ...
            log.exception("Run %s crashed", run_id)
            self._set_status(run_id, "failed", f"{type(exc).__name__}: {exc}", finished=True)
        finally:
            if provider is not None:
                await provider.aclose()

    async def _worker(self, run: Any, opts: Dict[str, Any], provider: Provider, ctl: RunControl,
                      queue: "asyncio.Queue[int]") -> None:
        while not ctl.stopped:
            try:
                result_id = queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            await self._process(run, opts, provider, ctl, result_id)

    async def _sleep(self, ctl: RunControl, seconds: float) -> None:
        end = time.monotonic() + seconds
        while time.monotonic() < end and not ctl.cancel:
            await asyncio.sleep(min(0.2, max(0.0, end - time.monotonic())))

    async def _call(self, provider: Provider, model: str, prompt: str, opts: Dict[str, Any],
                    ctl: RunControl, max_tokens: Optional[int] = None, temperature: Optional[float] = None) -> GenResult:
        retries = int(opts.get("max_retries", 3))
        for attempt in range(retries + 1):
            try:
                return await provider.generate(
                    prompt, model, temperature if temperature is not None else opts.get("temperature", 0.0),
                    max_tokens or opts.get("max_tokens", 4096), {"num_ctx": opts.get("num_ctx")})
            except ProviderError as exc:
                if not exc.retryable or attempt >= retries:
                    raise
                delay = exc.retry_after if exc.retry_after is not None else min(RETRY_BASE_DELAY * (2 ** attempt), 30)
                await self._sleep(ctl, min(delay, 60))
        raise ProviderError("Retries exhausted.")  # unreachable

    def _fail(self, ctl: RunControl, result_id: int, message: str) -> None:
        self.db.x("UPDATE results SET status='error', error=?, finished_at=? WHERE id=?",
                  (message[:1000], now_iso(), result_id))
        ctl.consecutive_errors += 1
        if ctl.consecutive_errors >= ABORT_AFTER and ctl.abort_reason is None:
            ctl.abort_reason = (f"Stopped after {ABORT_AFTER} failures in a row. Last error: {message[:300]}")

    async def _process(self, run: Any, opts: Dict[str, Any], provider: Provider, ctl: RunControl, result_id: int) -> None:
        row = self.db.q1(
            "SELECT r.id, r.variant, r.expected, r.strategy, p.template, s.cwe, s.project, s.category, "
            "CASE WHEN r.variant='vuln' THEN s.vulnerable_code ELSE s.patched_code END AS code "
            "FROM results r JOIN samples s ON s.id=r.sample_id JOIN prompts p ON p.id=r.prompt_id WHERE r.id=?",
            (result_id,))
        if row is None:
            return
        code, truncated, skipped = apply_input_policy(row["code"], opts.get("max_input_chars"), opts.get("input_policy", "truncate"))
        if skipped:
            self.db.x("UPDATE results SET status='skipped', error=?, input_chars=?, finished_at=? WHERE id=?",
                      (f"Input of {len(code)} characters exceeds the limit of {opts.get('max_input_chars')}.",
                       len(code), now_iso(), result_id))
            return
        prompt = render_prompt(row["template"], code, row["cwe"], row["project"] or "", row["category"] or "")
        started = time.perf_counter()
        try:
            gen = await self._call(provider, run["model"], prompt, opts, ctl)
            verdict, method = parse_verdict(gen.text, allow_bare="one word" in row["template"].lower())
            if verdict == AMBIGUOUS and opts.get("judge") and gen.text.strip():
                judge_model = opts.get("judge_model") or run["model"]
                judged = await self._call(provider, judge_model, JUDGE_PROMPT.replace("{analysis}", gen.text[-6000:]),
                                          opts, ctl, max_tokens=512, temperature=0.0)
                verdict = parse_judge(judged.text)
                method = "judge" if verdict != AMBIGUOUS else "none"
        except asyncio.CancelledError:
            raise
        except ProviderError as exc:
            self._fail(ctl, result_id, str(exc))
            return
        except Exception as exc:
            log.exception("Unexpected error on result %s", result_id)
            self._fail(ctl, result_id, f"Unexpected error: {type(exc).__name__}: {exc}")
            return
        latency = int((time.perf_counter() - started) * 1000)
        ctl.consecutive_errors = 0
        self.db.x(
            "UPDATE results SET status='done', verdict=?, correct=?, parse_method=?, response=?, error=NULL, "
            "latency_ms=?, input_chars=?, truncated=?, prompt_tokens=?, completion_tokens=?, finished_at=? WHERE id=?",
            (verdict, 1 if verdict == row["expected"] else 0, method, gen.text, latency, len(code),
             1 if truncated else 0, gen.prompt_tokens, gen.completion_tokens, now_iso(), result_id))
