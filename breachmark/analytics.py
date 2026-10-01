"""Metrics, leaderboards, breakdowns and ensembles computed from stored results."""
from __future__ import annotations

import math
from collections import defaultdict
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .db import Database
from .runs import get_run

Row = Dict[str, Any]


def wilson(successes: int, n: int, z: float = 1.96) -> Tuple[Optional[float], Optional[float]]:
    if n == 0:
        return None, None
    p = successes / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    margin = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return max(0.0, centre - margin), min(1.0, centre + margin)


def _rate(a: int, b: int) -> Optional[float]:
    return a / b if b else None


def fetch_rows(db: Database, run_ids: Sequence[int]) -> List[Row]:
    if not run_ids:
        return []
    marks = ",".join("?" * len(run_ids))
    rows = db.q(
        f"SELECT r.run_id, r.sample_id, r.strategy, r.variant, r.expected, r.status, r.verdict, r.correct, "
        f"r.latency_ms, r.prompt_tokens, r.completion_tokens, r.truncated, "
        f"s.cwe, s.project, s.year, s.noise, s.granularity, s.dataset, s.language "
        f"FROM results r JOIN samples s ON s.id = r.sample_id WHERE r.run_id IN ({marks}) AND r.status != 'pending'",
        list(run_ids))
    return [dict(r) for r in rows]


def compute_metrics(rows: Iterable[Row]) -> Dict[str, Any]:
    rows = list(rows)
    done = [r for r in rows if r["status"] == "done"]
    vuln = [r for r in done if r["variant"] == "vuln"]
    patch = [r for r in done if r["variant"] == "patch"]
    confusion = {
        "vuln": {"yes": sum(r["verdict"] == 1 for r in vuln), "no": sum(r["verdict"] == 0 for r in vuln),
                 "amb": sum(r["verdict"] == 2 for r in vuln)},
        "patch": {"yes": sum(r["verdict"] == 1 for r in patch), "no": sum(r["verdict"] == 0 for r in patch),
                  "amb": sum(r["verdict"] == 2 for r in patch)},
    }
    n = len(done)
    correct = sum(1 for r in done if r["correct"])
    tp, fp = confusion["vuln"]["yes"], confusion["patch"]["yes"]
    tpr = _rate(tp, len(vuln))
    tnr = _rate(confusion["patch"]["no"], len(patch))
    precision = _rate(tp, tp + fp)
    f1 = (2 * precision * tpr / (precision + tpr)) if precision and tpr else (0.0 if precision is not None and tpr is not None else None)
    by_sample: Dict[Any, Dict[str, int]] = defaultdict(dict)
    for r in done:
        by_sample[r["sample_id"]][r["variant"]] = r["verdict"]
    pairs = [v for v in by_sample.values() if "vuln" in v and "patch" in v]
    pair_ok = sum(1 for v in pairs if v["vuln"] == 1 and v["patch"] == 0)
    lo, hi = wilson(correct, n)
    latencies = [r["latency_ms"] for r in done if r["latency_ms"] is not None]
    return {
        "n": n, "n_vuln": len(vuln), "n_patch": len(patch),
        "errors": sum(r["status"] == "error" for r in rows), "skipped": sum(r["status"] == "skipped" for r in rows),
        "accuracy": _rate(correct, n), "acc_lo": lo, "acc_hi": hi,
        "tpr": tpr, "tnr": tnr, "balanced": (tpr + tnr) / 2 if tpr is not None and tnr is not None else None,
        "precision": precision, "f1": f1, "ambiguous_rate": _rate(sum(r["verdict"] == 2 for r in done), n),
        "pair_n": len(pairs), "pair_correct": _rate(pair_ok, len(pairs)), "confusion": confusion,
        "avg_latency_ms": sum(latencies) / len(latencies) if latencies else None,
        "prompt_tokens": sum(r["prompt_tokens"] or 0 for r in done),
        "completion_tokens": sum(r["completion_tokens"] or 0 for r in done),
        "truncated": sum(1 for r in done if r["truncated"]),
    }


def metrics_by_strategy(db: Database, run_id: int) -> Dict[str, Dict[str, Any]]:
    groups: Dict[str, List[Row]] = defaultdict(list)
    for r in fetch_rows(db, [run_id]):
        groups[r["strategy"]].append(r)
    return {s: compute_metrics(rows) for s, rows in sorted(groups.items())}


def cost_estimate(run: Dict[str, Any], metrics: Dict[str, Any]) -> Optional[float]:
    p_in, p_out = run["options"].get("price_in"), run["options"].get("price_out")
    if p_in is None and p_out is None:
        return None
    return (metrics["prompt_tokens"] * (p_in or 0) + metrics["completion_tokens"] * (p_out or 0)) / 1_000_000


def leaderboard(db: Database, run_ids: Optional[Sequence[int]] = None, sort: str = "accuracy") -> List[Dict[str, Any]]:
    """One entry per (run, strategy), best first."""
    if run_ids is None:
        run_ids = [r["id"] for r in db.q("SELECT id FROM runs")]
    entries: List[Dict[str, Any]] = []
    rows = fetch_rows(db, run_ids)
    groups: Dict[Tuple[int, str], List[Row]] = defaultdict(list)
    for r in rows:
        groups[(r["run_id"], r["strategy"])].append(r)
    runs = {rid: get_run(db, rid) for rid in run_ids}
    for (rid, strategy), rs in groups.items():
        run = runs[rid]
        m = compute_metrics(rs)
        if m["n"] == 0:
            continue
        entries.append({"run_id": rid, "run_name": run["name"], "provider": run["provider"], "model": run["model"],
                        "status": run["status"], "strategy": strategy, "cost": cost_estimate(run, m),
                        "blind": bool(run["options"].get("blind")), **m})
    entries.sort(key=lambda e: (e.get(sort) is None, -(e.get(sort) or 0), e["run_id"], e["strategy"]))
    return entries


def _bucket_noise(v: Optional[float]) -> str:
    if v is None:
        return "unknown"
    return "0%" if v == 0 else "1-20%" if v <= 20 else "21-50%" if v <= 50 else "51%+"


def _bucket_year(v: Optional[int]) -> str:
    if v is None:
        return "unknown"
    return "2009 or earlier" if v <= 2009 else "2010-2014" if v <= 2014 else "2015 or later"


def breakdown(rows: Iterable[Row], field: str) -> List[Dict[str, Any]]:
    groups: Dict[str, List[Row]] = defaultdict(list)
    for r in rows:
        key = (_bucket_noise(r["noise"]) if field == "noise" else _bucket_year(r["year"]) if field == "year"
               else str(r.get(field) or "unknown"))
        groups[key].append(r)
    order = {"noise": ["0%", "1-20%", "21-50%", "51%+", "unknown"],
             "year": ["2009 or earlier", "2010-2014", "2015 or later", "unknown"]}.get(field)
    keys = sorted(groups, key=(lambda k: order.index(k)) if order else (lambda k: k))
    out = []
    for k in keys:
        m = compute_metrics(groups[k])
        out.append({"label": k, "n": m["n"], "accuracy": m["accuracy"], "tpr": m["tpr"], "tnr": m["tnr"],
                    "ambiguous_rate": m["ambiguous_rate"]})
    return out


def cwe_heatmap(rows: Iterable[Row], limit: int = 20) -> Dict[str, Any]:
    cells: Dict[Tuple[str, str], List[Row]] = defaultdict(list)
    totals: Dict[str, int] = defaultdict(int)
    strategies = set()
    for r in rows:
        if r["status"] != "done":
            continue
        cwe = r["cwe"] or "unknown"
        cells[(cwe, r["strategy"])].append(r)
        totals[cwe] += 1
        strategies.add(r["strategy"])
    cwes = sorted(totals, key=lambda c: (-totals[c], c))[:limit]
    strategies_sorted = sorted(strategies)
    grid = []
    for cwe in cwes:
        row = []
        for s in strategies_sorted:
            cell = cells.get((cwe, s), [])
            n = len(cell)
            row.append({"n": n, "accuracy": (sum(1 for r in cell if r["correct"]) / n) if n else None})
        grid.append({"cwe": cwe, "n": totals[cwe], "cells": row})
    return {"strategies": strategies_sorted, "rows": grid}


def ensemble_rows(rows: Iterable[Row], strategy: str, min_votes: int = 1) -> List[Row]:
    """Majority vote across runs for one strategy. Ties and all-ambiguous votes become ambiguous (2)."""
    votes: Dict[Tuple[int, str], List[int]] = defaultdict(list)
    meta: Dict[Tuple[int, str], Row] = {}
    for r in rows:
        if r["strategy"] != strategy or r["status"] != "done":
            continue
        key = (r["sample_id"], r["variant"])
        votes[key].append(r["verdict"])
        meta[key] = r
    out = []
    for key, vs in votes.items():
        if len(vs) < min_votes:
            continue
        yes, no = vs.count(1), vs.count(0)
        verdict = 1 if yes > no else 0 if no > yes else 2
        base = dict(meta[key])
        base.update({"verdict": verdict, "correct": 1 if verdict == base["expected"] else 0, "status": "done",
                     "run_id": 0, "latency_ms": None, "prompt_tokens": None, "completion_tokens": None, "truncated": 0})
        out.append(base)
    return out
