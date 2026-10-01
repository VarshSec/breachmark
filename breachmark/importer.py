"""Import the vulnerability dataset (CSV) into SQLite."""
from __future__ import annotations

import csv
from pathlib import Path
from typing import Any, Dict, Optional

from .db import Database

REQUIRED = ("COMMIT_HASH", "VULNERABLE_CODE_BLOCK", "PATCHED_CODE_BLOCK")


def _raise_csv_limit() -> None:
    # Some code blocks are > 250,000 characters; the default csv limit is 131,072.
    limit = 2**31 - 1
    while True:
        try:
            csv.field_size_limit(limit)
            return
        except OverflowError:
            limit //= 2


def _int(value: Any) -> Optional[int]:
    try:
        return int(float(str(value).strip()))
    except (TypeError, ValueError):
        return None


def _float(value: Any) -> Optional[float]:
    try:
        text = str(value).strip()
        return float(text) if text else None
    except (TypeError, ValueError):
        return None


def _norm(code: str) -> str:
    return (code or "").replace("\r\n", "\n").replace("\r", "\n")


def granularity(num_files: Optional[int], num_functions: Optional[int]) -> str:
    """Derived bucket: G1 one function in one file, G2 several functions in one file, G3 spans files
    (or changes outside any function). Close to, but not identical with, the paper's split."""
    files = num_files or 0
    funcs = num_functions or 0
    if files > 1 or funcs == 0:
        return "G3"
    return "G1" if funcs == 1 else "G2"


def import_dataset(db: Database, csv_path: Path, replace: bool = False) -> Dict[str, Any]:
    csv_path = Path(csv_path)
    if not csv_path.is_file():
        raise FileNotFoundError(f"Dataset file not found: {csv_path}")
    if replace and db.scalar("SELECT COUNT(*) FROM runs"):
        raise ValueError("Cannot replace the dataset while runs exist. Delete the runs first.")
    _raise_csv_limit()

    inserted = updated = skipped = 0
    batch = []
    with open(csv_path, newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        headers = {h.strip().upper() for h in (reader.fieldnames or [])}
        missing = [c for c in REQUIRED if c not in headers]
        if missing:
            raise ValueError(f"CSV is missing required columns: {', '.join(missing)}")
        for raw in reader:
            row = {(k or "").strip().upper(): v for k, v in raw.items()}
            commit = (row.get("COMMIT_HASH") or "").strip()
            vuln = _norm(row.get("VULNERABLE_CODE_BLOCK", ""))
            patch = _norm(row.get("PATCHED_CODE_BLOCK", ""))
            if not commit or not vuln.strip() or not patch.strip():
                skipped += 1
                continue
            nfiles = _int(row.get("NUM_FILES_CHANGED"))
            nfuncs = _int(row.get("NUM_FUNCTIONS_CHANGED"))
            batch.append((
                _int(row.get("ID")), commit, (row.get("VULNERABILITY_CVE") or "").strip() or None,
                _int(row.get("VULNERABILITY_YEAR")), (row.get("VULNERABILITY_CWE") or "").strip() or None,
                (row.get("VULNERABILITY_CATEGORY") or "").strip() or None,
                _norm(row.get("DESCRIPTION_IN_PATCH", "")).strip() or None,
                vuln, patch, nfiles, nfuncs, _int(row.get("NUM_LINES_ADDED")), _int(row.get("NUM_LINES_DELETED")),
                (row.get("PROJECT") or "").strip() or None,
                # The CSV's NUM_LINES_IN_*_CODE_BLOCK columns do not match the code; count the real lines.
                vuln.count("\n") + 1, patch.count("\n") + 1,
                len(vuln), len(patch), _float(row.get("NOISE_AMOUNT")),
                _norm(row.get("NOISE_REASONING", "")).strip() or None, granularity(nfiles, nfuncs),
            ))

    sql = """
        INSERT INTO samples (id, commit_hash, cve, year, cwe, category, description, vulnerable_code, patched_code,
            num_files, num_functions, lines_added, lines_deleted, project, vuln_lines, patch_lines,
            vuln_chars, patch_chars, noise, noise_reasoning, granularity)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(commit_hash) DO UPDATE SET
            cve=excluded.cve, year=excluded.year, cwe=excluded.cwe, category=excluded.category,
            description=excluded.description, vulnerable_code=excluded.vulnerable_code,
            patched_code=excluded.patched_code, num_files=excluded.num_files, num_functions=excluded.num_functions,
            lines_added=excluded.lines_added, lines_deleted=excluded.lines_deleted, project=excluded.project,
            vuln_lines=excluded.vuln_lines, patch_lines=excluded.patch_lines, vuln_chars=excluded.vuln_chars,
            patch_chars=excluded.patch_chars, noise=excluded.noise, noise_reasoning=excluded.noise_reasoning,
            granularity=excluded.granularity
    """
    with db.tx() as conn:
        if replace:
            conn.execute("DELETE FROM samples")
        before = conn.execute("SELECT COUNT(*) FROM samples").fetchone()[0]
        conn.executemany(sql, batch)
        after = conn.execute("SELECT COUNT(*) FROM samples").fetchone()[0]
    inserted = after - before
    updated = len(batch) - inserted
    db.set_meta("dataset_path", str(csv_path))
    return {"rows": len(batch), "inserted": inserted, "updated": updated, "skipped": skipped, "total": after}


def ensure_dataset(db: Database, csv_path: Optional[Path]) -> Optional[Dict[str, Any]]:
    """Import the bundled dataset on first start. Does nothing if samples already exist."""
    if db.scalar("SELECT COUNT(*) FROM samples"):
        return None
    if csv_path is None or not Path(csv_path).is_file():
        return None
    return import_dataset(db, csv_path)
