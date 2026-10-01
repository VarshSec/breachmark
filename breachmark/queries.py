"""Sample filtering and listing, shared by the explorer, the run creator and the API."""
from __future__ import annotations

import random
from typing import Any, Dict, List, Optional, Tuple

from .db import Database

SORTS = {
    "id": "id",
    "cve": "cve",
    "cwe": "CAST(SUBSTR(cwe, 5) AS INTEGER)",
    "year": "year",
    "noise": "noise",
    "size": "vuln_chars",
    "project": "project",
    "dataset": "dataset",
    "language": "language",
}


def _like(term: str) -> str:
    return "%" + term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def _split(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(v).strip() for v in value if str(v).strip()]
    return [v.strip() for v in str(value).split(",") if v.strip()]


def _num(value: Any) -> Optional[float]:
    try:
        return float(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


def build_where(filters: Dict[str, Any]) -> Tuple[str, List[Any]]:
    clauses: List[str] = []
    params: List[Any] = []
    q = (filters.get("q") or "").strip()
    if q:
        clauses.append(
            "(cve LIKE ? ESCAPE '\\' OR commit_hash LIKE ? ESCAPE '\\' OR description LIKE ? ESCAPE '\\' "
            "OR category LIKE ? ESCAPE '\\' OR cwe LIKE ? ESCAPE '\\')"
        )
        params += [_like(q)] * 5
    for field, column in (("cwe", "cwe"), ("project", "project"), ("granularity", "granularity"),
                          ("dataset", "dataset"), ("language", "language")):
        values = _split(filters.get(field))
        if values:
            clauses.append(f"{column} IN ({','.join('?' * len(values))})")
            params += values
    for field, column, op in (("year_min", "year", ">="), ("year_max", "year", "<="),
                              ("max_noise", "noise", "<="), ("min_noise", "noise", ">="),
                              ("max_chars", "MAX(vuln_chars, patch_chars)", "<=")):
        number = _num(filters.get(field))
        if number is not None:
            if column.startswith("MAX("):
                clauses.append("(CASE WHEN vuln_chars > patch_chars THEN vuln_chars ELSE patch_chars END) <= ?")
            else:
                clauses.append(f"{column} {op} ?")
            params.append(number)
    return (" WHERE " + " AND ".join(clauses)) if clauses else "", params


def select_sample_ids(db: Database, filters: Dict[str, Any], limit: Optional[int] = None, seed: Optional[int] = None) -> List[int]:
    where, params = build_where(filters or {})
    ids = [r["id"] for r in db.q(f"SELECT id FROM samples{where} ORDER BY id", params)]
    if seed is not None:
        random.Random(seed).shuffle(ids)
    if limit:
        ids = ids[: int(limit)]
    return ids


def count_samples(db: Database, filters: Dict[str, Any]) -> int:
    where, params = build_where(filters or {})
    return db.scalar(f"SELECT COUNT(*) FROM samples{where}", params) or 0


def list_samples(db: Database, filters: Dict[str, Any], page: int = 1, per_page: int = 25,
                 sort: str = "id", direction: str = "asc") -> Dict[str, Any]:
    where, params = build_where(filters or {})
    total = db.scalar(f"SELECT COUNT(*) FROM samples{where}", params) or 0
    column = SORTS.get(sort, "id")
    order = "DESC" if direction == "desc" else "ASC"
    page = max(1, page)
    rows = db.q(
        f"SELECT id, commit_hash, cve, year, cwe, category, project, num_files, num_functions, noise, "
        f"granularity, vuln_chars, patch_chars, dataset, language, function_name FROM samples{where} "
        f"ORDER BY {column} {order}, id ASC LIMIT ? OFFSET ?",
        params + [per_page, (page - 1) * per_page],
    )
    return {"rows": rows, "total": total, "page": page, "per_page": per_page,
            "pages": max(1, -(-total // per_page))}


def facets(db: Database) -> Dict[str, Any]:
    return {
        "cwes": db.q("SELECT cwe, COUNT(*) AS n FROM samples WHERE cwe IS NOT NULL GROUP BY cwe ORDER BY n DESC, cwe"),
        "projects": db.q("SELECT project, COUNT(*) AS n FROM samples WHERE project IS NOT NULL GROUP BY project ORDER BY n DESC"),
        "granularity": db.q("SELECT granularity, COUNT(*) AS n FROM samples GROUP BY granularity ORDER BY granularity"),
        "years": db.q1("SELECT MIN(year) AS lo, MAX(year) AS hi FROM samples"),
        "datasets": db.q("SELECT dataset, COUNT(*) AS n FROM samples GROUP BY dataset ORDER BY n DESC"),
        "languages": db.q("SELECT language, COUNT(*) AS n FROM samples GROUP BY language ORDER BY n DESC"),
        "total": db.scalar("SELECT COUNT(*) FROM samples") or 0,
    }
