import json
import sqlite3
from pathlib import Path

import pytest

from breachmark import importer, queries, runs
from breachmark.db import Database
from breachmark.prompts import render_prompt, seed_prompts

from conftest import DATASET, run_to_end

SVEN_DIR = DATASET.parent / "sven"

OLD_SCHEMA = """
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE samples (
    id INTEGER PRIMARY KEY, commit_hash TEXT NOT NULL UNIQUE, cve TEXT, year INTEGER, cwe TEXT, category TEXT,
    description TEXT, vulnerable_code TEXT NOT NULL, patched_code TEXT NOT NULL, num_files INTEGER,
    num_functions INTEGER, lines_added INTEGER, lines_deleted INTEGER, project TEXT, vuln_lines INTEGER,
    patch_lines INTEGER, vuln_chars INTEGER, patch_chars INTEGER, noise REAL, noise_reasoning TEXT, granularity TEXT);
CREATE TABLE prompts (id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT NOT NULL, version INTEGER NOT NULL, name TEXT NOT NULL,
    description TEXT, template TEXT NOT NULL, builtin INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, UNIQUE (key, version));
CREATE TABLE runs (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, provider TEXT NOT NULL, model TEXT NOT NULL,
    options TEXT NOT NULL DEFAULT '{}', filters TEXT NOT NULL DEFAULT '{}', status TEXT NOT NULL DEFAULT 'pending', error TEXT,
    total_tasks INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, started_at TEXT, finished_at TEXT);
CREATE TABLE results (id INTEGER PRIMARY KEY AUTOINCREMENT, run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    sample_id INTEGER NOT NULL REFERENCES samples(id), variant TEXT NOT NULL, prompt_id INTEGER NOT NULL REFERENCES prompts(id),
    strategy TEXT NOT NULL, expected INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'pending', verdict INTEGER, correct INTEGER,
    parse_method TEXT, response TEXT, error TEXT, latency_ms INTEGER, input_chars INTEGER, truncated INTEGER NOT NULL DEFAULT 0,
    prompt_tokens INTEGER, completion_tokens INTEGER, finished_at TEXT, UNIQUE (run_id, sample_id, variant, strategy));
"""


def test_migration_from_single_dataset_schema(tmp_path):
    path = tmp_path / "old.db"
    conn = sqlite3.connect(path)
    conn.executescript(OLD_SCHEMA)
    conn.execute("INSERT INTO samples (id, commit_hash, cwe, vulnerable_code, patched_code, project, granularity) "
                 "VALUES (7, 'abc', 'CWE-1', 'v', 'p', 'linux', 'G1')")
    conn.execute("INSERT INTO prompts (key, version, name, template, builtin, created_at) VALUES ('cot', 1, 'c', 'x {code}', 1, 't')")
    conn.execute("INSERT INTO runs (id, name, provider, model, created_at) VALUES (1, 'r', 'mock', 'm', 't')")
    conn.execute("INSERT INTO results (run_id, sample_id, variant, prompt_id, strategy, expected, status, verdict, correct) "
                 "VALUES (1, 7, 'vuln', 1, 'cot', 1, 'done', 1, 1)")
    conn.commit()
    conn.close()

    db = Database(path)
    db.init()
    row = db.q1("SELECT id, dataset, sample_key, commit_hash, language, cwe FROM samples")
    assert tuple(row) == (7, "vulnsage", "abc", "abc", "C/C++", "CWE-1")
    # results still join to the migrated samples table and foreign keys still hold
    assert db.scalar("SELECT COUNT(*) FROM results r JOIN samples s ON s.id=r.sample_id") == 1
    with pytest.raises(sqlite3.IntegrityError):
        db.x("INSERT INTO results (run_id, sample_id, variant, prompt_id, strategy, expected) VALUES (1, 999, 'vuln', 1, 'cot', 1)")
    # new datasets can now be added next to the old rows
    importer.import_sven(db, SVEN_DIR)
    assert db.scalar("SELECT COUNT(DISTINCT dataset) FROM samples") == 2
    db.init()  # idempotent on an already migrated database


def test_sven_import_real_data(db):
    assert SVEN_DIR.is_dir()
    assert db.scalar("SELECT COUNT(*) FROM samples WHERE dataset='sven'") == 803
    langs = {r["language"]: r["n"] for r in db.q("SELECT language, COUNT(*) n FROM samples WHERE dataset='sven' GROUP BY 1")}
    assert langs == {"C/C++": 423, "Python": 380}
    assert db.scalar("SELECT COUNT(DISTINCT cwe) FROM samples WHERE dataset='sven'") == 9
    assert db.scalar("SELECT COUNT(*) FROM samples WHERE dataset='sven' AND cwe NOT LIKE 'CWE-%'") == 0
    s = db.q1("SELECT * FROM samples WHERE dataset='sven' AND language='Python' LIMIT 1")
    assert s["source_url"].startswith("https://github.com/") and "/commit/" in s["source_url"]
    assert s["function_name"] and s["granularity"] == "G1" and s["vulnerable_code"] != s["patched_code"]
    again = importer.import_sven(db, SVEN_DIR)
    assert (again["inserted"], again["updated"]) == (0, 803)


def test_primevul_import_from_paired_jsonl(db, tmp_path):
    def rec(idx, commit, target, func, **extra):
        base = {"idx": idx, "project": "proj", "commit_id": commit, "target": target, "func": func, "func_hash": f"h{idx}",
                "file_name": "src/x.c", "cwe": ["CWE-125"], "cve": "CVE-2019-0001", "cve_desc": "Out-of-bounds read.",
                "commit_url": f"https://github.com/o/proj/commit/{commit}", "commit_message": "fix"}
        base.update(extra)
        return base
    records = [
        rec(1, "c1", 1, "int a(){ return buf[i]; }"), rec(2, "c1", 0, "int a(){ if(i<n) return buf[i]; return 0; }"),
        rec(3, "c2", 0, "int lonely(){ return 0; }"),                           # benign without a vulnerable partner
        rec(4, "c3", 1, "void b(){ strcpy(d,s); }", cwe=["CWE-787"], cve=""), rec(5, "c3", 0, "void b(){ strncpy(d,s,n); }"),
        rec(6, "c4", 1, "void c(){}"), rec(7, "c5", 0, "void c(){}"),           # different commits: not a pair
    ]
    f = tmp_path / "primevul_test_paired.jsonl"
    f.write_text("\n".join(json.dumps(r) for r in records) + "\n")
    result = importer.import_primevul(db, f)
    assert result["rows"] == 2 and result["inserted"] == 2
    rows = db.q("SELECT commit_hash, cve, year, cwe, project, language, description FROM samples WHERE dataset='primevul' ORDER BY id")
    assert tuple(rows[0]) == ("c1", "CVE-2019-0001", 2019, "CWE-125", "proj", "C/C++", "Out-of-bounds read.")
    assert rows[1]["cwe"] == "CWE-787" and rows[1]["cve"] is None and rows[1]["year"] is None
    (tmp_path / "bad.jsonl").write_text(json.dumps(rec(9, "c9", 0, "x")) + "\n")
    with pytest.raises(ValueError, match="No vulnerable/fixed pairs"):
        importer.import_primevul(db, tmp_path / "bad.jsonl")
    with pytest.raises(ValueError, match="Unknown format"):
        importer.import_any(db, "nope", f)


def test_language_reaches_the_prompt(db, manager):
    tpl = db.q1("SELECT template FROM prompts WHERE key='think'")["template"]
    assert "{language}" in tpl and "```c" not in tpl
    assert "reviewing Python source code" in render_prompt(tpl, "x", "CWE-89", language="Python")
    rid = runs.create_run(db, {"provider": "mock", "model": "mock-balanced", "strategies": ["cot"], "limit": 4,
                               "filters": {"dataset": "sven", "language": "Python"}})
    run_to_end(manager, rid)
    assert db.scalar("SELECT COUNT(*) FROM results r JOIN samples s ON s.id=r.sample_id "
                     "WHERE r.run_id=? AND s.language!='Python'", (rid,)) == 0


def test_dataset_filters_and_facets(db):
    assert queries.count_samples(db, {"dataset": "vulnsage"}) == 593
    assert queries.count_samples(db, {"dataset": "sven"}) == 803
    assert queries.count_samples(db, {"language": "Python"}) == 380
    assert queries.count_samples(db, {"dataset": "sven", "cwe": "CWE-89"}) == 204
    facets = queries.facets(db)
    assert {r["dataset"] for r in facets["datasets"]} == {"vulnsage", "sven"}
    assert facets["total"] == 1396
    summary = {d["dataset"]: d for d in importer.dataset_summary(db)}
    assert summary["sven"]["languages"] == ["C/C++", "Python"] and summary["vulnsage"]["cwes"] == 52
