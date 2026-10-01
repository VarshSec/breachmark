"""Import vulnerability datasets into SQLite.

Supported formats:
- vulnsage: the VulnSage CSV (593 C/C++ vulnerabilities, file or function level)
- sven: the SVEN data_train_val JSONL files (803 C/C++ and Python function pairs)
- primevul: PrimeVul *_paired.jsonl files (consecutive vulnerable/benign function pairs)

Every importer produces rows with the same shape and upserts them by (dataset, sample_key),
so re-importing updates in place and never duplicates.
"""
from __future__ import annotations

import csv
import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .db import Database

REQUIRED = ("COMMIT_HASH", "VULNERABLE_CODE_BLOCK", "PATCHED_CODE_BLOCK")
FORMATS = ("vulnsage", "sven", "primevul")

LANG_BY_EXT = {"c": "C/C++", "h": "C/C++", "cc": "C/C++", "cpp": "C/C++", "cxx": "C/C++", "hpp": "C/C++",
               "py": "Python", "java": "Java", "js": "JavaScript", "ts": "TypeScript", "go": "Go", "rb": "Ruby",
               "php": "PHP", "rs": "Rust", "cs": "C#", "swift": "Swift", "kt": "Kotlin"}

COLUMNS = ["dataset", "sample_key", "commit_hash", "cve", "year", "cwe", "category", "description", "vulnerable_code",
           "patched_code", "num_files", "num_functions", "lines_added", "lines_deleted", "project", "language",
           "function_name", "source_url", "vuln_lines", "patch_lines", "vuln_chars", "patch_chars", "noise",
           "noise_reasoning", "granularity"]


def _raise_csv_limit() -> None:
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
    """G1 one function in one file, G2 several functions in one file, G3 spans files (or no function)."""
    files = num_files or 0
    funcs = num_functions or 0
    if files > 1 or funcs == 0:
        return "G3"
    return "G1" if funcs == 1 else "G2"


def language_from_filename(name: str) -> str:
    ext = (name or "").rsplit(".", 1)[-1].lower() if "." in (name or "") else ""
    return LANG_BY_EXT.get(ext, "Unknown")


def _row(dataset: str, key: str, vuln: str, patch: str, **fields: Any) -> Dict[str, Any]:
    vuln, patch = _norm(vuln), _norm(patch)
    nfiles = fields.get("num_files")
    nfuncs = fields.get("num_functions")
    row = {c: None for c in COLUMNS}
    row.update(fields)
    row.update({"dataset": dataset, "sample_key": key, "vulnerable_code": vuln, "patched_code": patch,
                "vuln_lines": vuln.count("\n") + 1, "patch_lines": patch.count("\n") + 1,
                "vuln_chars": len(vuln), "patch_chars": len(patch),
                "granularity": fields.get("granularity") or granularity(nfiles, nfuncs),
                "language": fields.get("language") or "C/C++"})
    return row


def _upsert(db: Database, dataset: str, rows: List[Dict[str, Any]], replace: bool, source: str) -> Dict[str, Any]:
    if replace and db.scalar("SELECT COUNT(*) FROM runs"):
        raise ValueError("Cannot replace a dataset while runs exist. Delete the runs first.")
    sql = (f"INSERT INTO samples ({', '.join(COLUMNS)}) VALUES ({', '.join('?' * len(COLUMNS))}) "
           f"ON CONFLICT(dataset, sample_key) DO UPDATE SET " +
           ", ".join(f"{c}=excluded.{c}" for c in COLUMNS if c not in ("dataset", "sample_key")))
    with db.tx() as conn:
        if replace:
            conn.execute("DELETE FROM samples WHERE dataset=?", (dataset,))
        before = conn.execute("SELECT COUNT(*) FROM samples WHERE dataset=?", (dataset,)).fetchone()[0]
        conn.executemany(sql, [[r[c] for c in COLUMNS] for r in rows])
        after = conn.execute("SELECT COUNT(*) FROM samples WHERE dataset=?", (dataset,)).fetchone()[0]
        total = conn.execute("SELECT COUNT(*) FROM samples").fetchone()[0]
    db.set_meta(f"dataset_path:{dataset}", source)
    inserted = after - before
    return {"dataset": dataset, "rows": len(rows), "inserted": inserted, "updated": len(rows) - inserted,
            "in_dataset": after, "total": total}


# ----------------------------------------------------------------------------- VulnSage CSV
def read_vulnsage(csv_path: Path) -> List[Dict[str, Any]]:
    _raise_csv_limit()
    rows: List[Dict[str, Any]] = []
    with open(csv_path, newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        headers = {h.strip().upper() for h in (reader.fieldnames or [])}
        missing = [c for c in REQUIRED if c not in headers]
        if missing:
            raise ValueError(f"CSV is missing required columns: {', '.join(missing)}")
        for raw in reader:
            r = {(k or "").strip().upper(): v for k, v in raw.items()}
            commit = (r.get("COMMIT_HASH") or "").strip()
            vuln, patch = r.get("VULNERABLE_CODE_BLOCK", ""), r.get("PATCHED_CODE_BLOCK", "")
            if not commit or not (vuln or "").strip() or not (patch or "").strip():
                continue
            nfiles, nfuncs = _int(r.get("NUM_FILES_CHANGED")), _int(r.get("NUM_FUNCTIONS_CHANGED"))
            rows.append(_row("vulnsage", commit, vuln, patch, commit_hash=commit,
                             cve=(r.get("VULNERABILITY_CVE") or "").strip() or None, year=_int(r.get("VULNERABILITY_YEAR")),
                             cwe=(r.get("VULNERABILITY_CWE") or "").strip() or None,
                             category=(r.get("VULNERABILITY_CATEGORY") or "").strip() or None,
                             description=_norm(r.get("DESCRIPTION_IN_PATCH", "")).strip() or None,
                             num_files=nfiles, num_functions=nfuncs, lines_added=_int(r.get("NUM_LINES_ADDED")),
                             lines_deleted=_int(r.get("NUM_LINES_DELETED")), project=(r.get("PROJECT") or "").strip() or None,
                             language="C/C++", noise=_float(r.get("NOISE_AMOUNT")),
                             noise_reasoning=_norm(r.get("NOISE_REASONING", "")).strip() or None))
    return rows


def import_dataset(db: Database, csv_path: Path, replace: bool = False) -> Dict[str, Any]:
    """Import the VulnSage CSV (kept under its original name for compatibility)."""
    csv_path = Path(csv_path)
    if not csv_path.is_file():
        raise FileNotFoundError(f"Dataset file not found: {csv_path}")
    rows = read_vulnsage(csv_path)
    result = _upsert(db, "vulnsage", rows, replace, str(csv_path))
    db.set_meta("dataset_path", str(csv_path))
    return result


# ----------------------------------------------------------------------------- SVEN
def _jsonl_files(path: Path) -> List[Path]:
    path = Path(path)
    if path.is_file():
        return [path]
    if path.is_dir():
        files = sorted(path.rglob("*.jsonl"))
        if not files:
            raise FileNotFoundError(f"No .jsonl files found under {path}")
        return files
    raise FileNotFoundError(f"Not found: {path}")


def read_sven(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    seen: Dict[str, int] = {}
    for file in _jsonl_files(path):
        with open(file, encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                d = json.loads(line)
                vuln, patch = d.get("func_src_before") or "", d.get("func_src_after") or ""
                if not vuln.strip() or not patch.strip():
                    continue
                link = (d.get("commit_link") or "").strip()
                commit = link.rsplit("/commit/", 1)[-1] if "/commit/" in link else None
                project = None
                m = re.search(r"github\.com/([^/]+/[^/]+)/commit/", link)
                if m:
                    project = m.group(1)
                base = f"{commit or 'nocommit'}:{d.get('file_name', '')}:{d.get('func_name', '')}"
                seen[base] = seen.get(base, 0) + 1
                key = base if seen[base] == 1 else f"{base}#{seen[base]}"
                changes = d.get("line_changes") or {}
                cwe = (d.get("vul_type") or "").upper().replace("CWE-0", "CWE-").replace("CWE-", "CWE-") or None
                if cwe and re.match(r"CWE-\d+", cwe):
                    cwe = "CWE-" + str(int(cwe.split("-")[1]))
                rows.append(_row("sven", key, vuln, patch, commit_hash=commit, cwe=cwe, project=project,
                                 language=language_from_filename(d.get("file_name", "")),
                                 function_name=d.get("func_name"), num_files=1, num_functions=1,
                                 lines_added=len(changes.get("added") or []), lines_deleted=len(changes.get("deleted") or []),
                                 source_url=("https://" + link) if link and not link.startswith("http") else (link or None),
                                 description=d.get("file_name") or None))
    return rows


def import_sven(db: Database, path: Path, replace: bool = False) -> Dict[str, Any]:
    return _upsert(db, "sven", read_sven(Path(path)), replace, str(path))


# ----------------------------------------------------------------------------- PrimeVul
def read_primevul(path: Path) -> List[Dict[str, Any]]:
    """PrimeVul *_paired.jsonl: a vulnerable function (target 1) immediately followed by its fixed
    version (target 0) from the same commit. Records that do not form such a pair are skipped."""
    rows: List[Dict[str, Any]] = []
    seen: Dict[str, int] = {}
    for file in _jsonl_files(path):
        records = []
        with open(file, encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
        i = 0
        while i < len(records) - 1:
            a, b = records[i], records[i + 1]
            if int(a.get("target", -1)) == 1 and int(b.get("target", -1)) == 0 and a.get("commit_id") == b.get("commit_id"):
                vuln, patch = a.get("func") or "", b.get("func") or ""
                if vuln.strip() and patch.strip():
                    commit = a.get("commit_id")
                    cwes = a.get("cwe") or []
                    if isinstance(cwes, str):
                        cwes = [cwes]
                    cve = (a.get("cve") or "").strip() or None
                    year = None
                    if cve:
                        m = re.match(r"CVE-(\d{4})-", cve)
                        year = int(m.group(1)) if m else None
                    base = f"{commit}:{a.get('func_hash') or a.get('idx')}"
                    seen[base] = seen.get(base, 0) + 1
                    key = base if seen[base] == 1 else f"{base}#{seen[base]}"
                    rows.append(_row("primevul", key, vuln, patch, commit_hash=commit, cve=cve, year=year,
                                     cwe=(cwes[0].strip().upper() if cwes else None), project=a.get("project"),
                                     description=(a.get("cve_desc") or a.get("commit_message") or "").strip()[:2000] or None,
                                     language=language_from_filename(a.get("file_name", "")) if a.get("file_name") else "C/C++",
                                     num_files=1, num_functions=1, source_url=a.get("commit_url") or a.get("nvd_url")))
                i += 2
            else:
                i += 1
    if not rows:
        raise ValueError("No vulnerable/fixed pairs found. Use the *_paired.jsonl files from the PrimeVul release.")
    return rows


def import_primevul(db: Database, path: Path, replace: bool = False) -> Dict[str, Any]:
    return _upsert(db, "primevul", read_primevul(Path(path)), replace, str(path))


# ----------------------------------------------------------------------------- dispatch
def import_any(db: Database, fmt: str, path: Path, replace: bool = False) -> Dict[str, Any]:
    if fmt == "vulnsage":
        return import_dataset(db, path, replace)
    if fmt == "sven":
        return import_sven(db, path, replace)
    if fmt == "primevul":
        return import_primevul(db, path, replace)
    raise ValueError(f"Unknown format '{fmt}'. Choose one of: {', '.join(FORMATS)}")


def dataset_summary(db: Database) -> List[Dict[str, Any]]:
    rows = db.q("SELECT dataset, COUNT(*) AS n, COUNT(DISTINCT cwe) AS cwes, COUNT(DISTINCT language) AS langs, "
                "GROUP_CONCAT(DISTINCT language) AS languages FROM samples GROUP BY dataset ORDER BY dataset")
    out = []
    for r in rows:
        out.append({"dataset": r["dataset"], "n": r["n"], "cwes": r["cwes"],
                    "languages": sorted((r["languages"] or "").split(",")),
                    "path": db.get_meta(f"dataset_path:{r['dataset']}")})
    return out


def ensure_dataset(db: Database, csv_path: Optional[Path]) -> Optional[Dict[str, Any]]:
    """On first start import the bundled datasets: the VulnSage CSV and, if present, data/sven next to it."""
    if db.scalar("SELECT COUNT(*) FROM samples"):
        return None
    if csv_path is None or not Path(csv_path).is_file():
        return None
    result = import_dataset(db, csv_path)
    sven_dir = Path(csv_path).parent / "sven"
    if sven_dir.is_dir():
        try:
            result["sven"] = import_sven(db, sven_dir)
        except (ValueError, FileNotFoundError, json.JSONDecodeError):
            pass
    return result
