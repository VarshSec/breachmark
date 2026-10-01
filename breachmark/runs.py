"""Creating, inspecting and managing benchmark runs."""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, List, Optional

from .db import Database, now_iso
from .prompts import latest_prompt_ids, strategy_label
from .providers import PROVIDER_CLASSES
from .queries import select_sample_ids

VARIANTS = ("vuln", "patch")
INPUT_POLICIES = ("truncate", "skip", "none")

DEFAULT_OPTIONS: Dict[str, Any] = {
    "temperature": 0.0,
    "max_tokens": 4096,
    "num_ctx": 16384,          # Ollama only
    "max_input_chars": 40000,  # ~12k tokens of C code; 0 disables the limit
    "input_policy": "truncate",
    "concurrency": None,       # None = provider default
    "max_retries": 3,
    "timeout": 300,
    "judge": False,
    "judge_model": None,
    "base_url": None,
    "price_in": None,          # optional USD per 1M tokens, for cost estimates
    "price_out": None,
}


def _number(opts: Dict[str, Any], key: str, kind, lo, hi, default):
    value = opts.get(key, default)
    if value in (None, ""):
        return default
    try:
        value = kind(value)
    except (TypeError, ValueError):
        raise ValueError(f"Option '{key}' must be a number.")
    if not (lo <= value <= hi):
        raise ValueError(f"Option '{key}' must be between {lo} and {hi}.")
    return value


def normalize_options(provider: str, raw: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    raw = dict(raw or {})
    opts = dict(DEFAULT_OPTIONS)
    opts["temperature"] = _number(raw, "temperature", float, 0.0, 2.0, 0.0)
    opts["max_tokens"] = _number(raw, "max_tokens", int, 16, 200000, 4096)
    opts["num_ctx"] = _number(raw, "num_ctx", int, 512, 2_000_000, 16384)
    opts["max_input_chars"] = _number(raw, "max_input_chars", int, 0, 10_000_000, 40000)
    opts["max_retries"] = _number(raw, "max_retries", int, 0, 8, 3)
    opts["timeout"] = _number(raw, "timeout", int, 5, 7200, 300)
    default_conc = PROVIDER_CLASSES[provider].default_concurrency
    opts["concurrency"] = _number(raw, "concurrency", int, 1, 64, default_conc)
    policy = raw.get("input_policy") or "truncate"
    if policy not in INPUT_POLICIES:
        raise ValueError(f"input_policy must be one of {', '.join(INPUT_POLICIES)}.")
    opts["input_policy"] = policy
    opts["judge"] = bool(raw.get("judge"))
    opts["judge_model"] = (raw.get("judge_model") or "").strip() or None
    base_url = (raw.get("base_url") or "").strip()
    if base_url and not base_url.lower().startswith(("http://", "https://")):
        raise ValueError("Base URL must start with http:// or https://")
    opts["base_url"] = base_url.rstrip("/") or None
    for key in ("price_in", "price_out"):
        value = raw.get(key)
        opts[key] = float(value) if value not in (None, "") else None
    return opts


def _resolve_prompts(db: Database, spec: Dict[str, Any]):
    if spec.get("prompt_ids"):
        ids = [int(i) for i in spec["prompt_ids"]]
    else:
        keys = spec.get("strategies") or []
        if not keys:
            raise ValueError("Choose at least one prompt strategy.")
        ids = latest_prompt_ids(db, list(keys))
    rows = []
    for pid in ids:
        row = db.q1("SELECT id, key, version FROM prompts WHERE id=?", (pid,))
        if row is None:
            raise ValueError(f"Prompt {pid} does not exist.")
        rows.append(row)
    return rows


def _validate_spec(spec: Dict[str, Any]):
    provider = spec.get("provider")
    if provider not in PROVIDER_CLASSES:
        raise ValueError(f"Unknown provider '{provider}'.")
    model = (spec.get("model") or "").strip()
    if not model:
        raise ValueError("Enter a model name.")
    variants = list(spec.get("variants") or VARIANTS)
    if not variants or any(v not in VARIANTS for v in variants):
        raise ValueError("Variants must be 'vuln' and/or 'patch'.")
    return provider, model, variants


def estimate(db: Database, spec: Dict[str, Any]) -> Dict[str, Any]:
    provider, model, variants = _validate_spec(spec)
    opts = normalize_options(provider, spec.get("options"))
    prompts = _resolve_prompts(db, spec)
    ids = select_sample_ids(db, spec.get("filters") or {}, spec.get("limit"), spec.get("shuffle_seed"))
    chars = 0
    if ids:
        cap = opts["max_input_chars"] or None
        for start in range(0, len(ids), 500):
            chunk = ids[start:start + 500]
            for r in db.q(f"SELECT vuln_chars, patch_chars FROM samples WHERE id IN ({','.join('?' * len(chunk))})", chunk):
                for variant, size in (("vuln", r["vuln_chars"]), ("patch", r["patch_chars"])):
                    if variant in variants:
                        chars += min(size, cap) if cap and opts["input_policy"] == "truncate" else size
    requests_total = len(ids) * len(variants) * len(prompts)
    return {"samples": len(ids), "requests": requests_total,
            "approx_input_tokens": int(chars * len(prompts) / 3.5)}


def create_run(db: Database, spec: Dict[str, Any]) -> int:
    provider, model, variants = _validate_spec(spec)
    opts = normalize_options(provider, spec.get("options"))
    prompts = _resolve_prompts(db, spec)
    filters = spec.get("filters") or {}
    ids = select_sample_ids(db, filters, spec.get("limit"), spec.get("shuffle_seed"))
    if not ids:
        raise ValueError("No samples match these filters.")
    name = (spec.get("name") or "").strip() or f"{model} {datetime.now().strftime('%Y-%m-%d %H:%M')}"
    total = len(ids) * len(variants) * len(prompts)
    with db.tx() as conn:
        run_id = conn.execute(
            "INSERT INTO runs(name, provider, model, options, filters, status, total_tasks, created_at) "
            "VALUES(?,?,?,?,?,'pending',?,?)",
            (name, provider, model, json.dumps(opts), json.dumps({**filters, "limit": spec.get("limit"),
             "shuffle_seed": spec.get("shuffle_seed")}), total, now_iso()),
        ).lastrowid
        rows = [(run_id, sid, variant, p["id"], strategy_label(p["key"], p["version"]), 1 if variant == "vuln" else 0)
                for sid in ids for variant in variants for p in prompts]
        conn.executemany(
            "INSERT INTO results(run_id, sample_id, variant, prompt_id, strategy, expected) VALUES(?,?,?,?,?,?)", rows)
    return run_id


def get_run(db: Database, run_id: int) -> Optional[Dict[str, Any]]:
    row = db.q1("SELECT * FROM runs WHERE id=?", (run_id,))
    if row is None:
        return None
    run = dict(row)
    run["options"] = json.loads(run["options"] or "{}")
    run["filters"] = json.loads(run["filters"] or "{}")
    return run


def list_runs(db: Database) -> List[Dict[str, Any]]:
    return [dict(r) for r in db.q("SELECT id, name, provider, model, status, total_tasks, created_at, finished_at "
                                  "FROM runs ORDER BY id DESC")]


def run_progress(db: Database, run_id: int) -> Optional[Dict[str, Any]]:
    run = get_run(db, run_id)
    if run is None:
        return None
    counts = {"pending": 0, "done": 0, "error": 0, "skipped": 0}
    for r in db.q("SELECT status, COUNT(*) AS n FROM results WHERE run_id=? GROUP BY status", (run_id,)):
        counts[r["status"]] = r["n"]
    total = sum(counts.values())
    finished = total - counts["pending"]
    avg = db.scalar("SELECT AVG(latency_ms) FROM results WHERE run_id=? AND status='done'", (run_id,))
    conc = run["options"].get("concurrency") or 1
    eta = int(counts["pending"] * (avg / 1000.0) / conc) if avg and run["status"] == "running" else None
    return {"id": run_id, "name": run["name"], "status": run["status"], "error": run["error"], "total": total,
            "finished": finished, "percent": round(100.0 * finished / total, 1) if total else 0.0,
            "counts": counts, "avg_latency_ms": int(avg) if avg else None, "eta_seconds": eta}


def reset_errors(db: Database, run_id: int) -> int:
    with db.tx() as conn:
        cur = conn.execute(
            "UPDATE results SET status='pending', error=NULL, verdict=NULL, correct=NULL, response=NULL "
            "WHERE run_id=? AND status IN ('error', 'skipped')", (run_id,))
        if cur.rowcount:
            conn.execute("UPDATE runs SET status='paused', finished_at=NULL WHERE id=? AND status IN "
                         "('completed','failed','cancelled')", (run_id,))
        return cur.rowcount


def delete_run(db: Database, run_id: int) -> None:
    db.x("DELETE FROM runs WHERE id=?", (run_id,))
