"""CSV export."""
from __future__ import annotations

import csv
import io
from typing import Iterator, Sequence

from .db import Database

COLUMNS = ["run_id", "run_name", "provider", "model", "strategy", "commit_hash", "cve", "cwe", "project", "variant",
           "expected", "verdict", "correct", "status", "parse_method", "latency_ms", "prompt_tokens",
           "completion_tokens", "truncated", "error"]


def results_csv(db: Database, run_ids: Sequence[int], include_response: bool = False) -> Iterator[str]:
    cols = COLUMNS + (["response"] if include_response else [])
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(cols)
    yield buf.getvalue()
    marks = ",".join("?" * len(run_ids))
    sql = (f"SELECT r.run_id, u.name AS run_name, u.provider, u.model, r.strategy, s.commit_hash, s.cve, s.cwe, "
           f"s.project, r.variant, r.expected, r.verdict, r.correct, r.status, r.parse_method, r.latency_ms, "
           f"r.prompt_tokens, r.completion_tokens, r.truncated, r.error, r.response "
           f"FROM results r JOIN runs u ON u.id=r.run_id JOIN samples s ON s.id=r.sample_id "
           f"WHERE r.run_id IN ({marks}) ORDER BY r.run_id, r.sample_id, r.variant, r.strategy")
    rows = db.q(sql, list(run_ids))
    for row in rows:
        buf.seek(0)
        buf.truncate()
        writer.writerow([row[c] for c in cols])
        yield buf.getvalue()
