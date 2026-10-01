"""SQLite access. One short-lived connection per operation keeps threads and asyncio simple."""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator, List, Optional, Sequence, Union

SCHEMA_HEAD = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
"""

SAMPLES_DDL = """
CREATE TABLE IF NOT EXISTS {name} (
    id INTEGER PRIMARY KEY,
    dataset TEXT NOT NULL DEFAULT 'vulnsage',
    sample_key TEXT NOT NULL,
    commit_hash TEXT,
    cve TEXT, year INTEGER, cwe TEXT, category TEXT, description TEXT,
    vulnerable_code TEXT NOT NULL,
    patched_code TEXT NOT NULL,
    num_files INTEGER, num_functions INTEGER, lines_added INTEGER, lines_deleted INTEGER,
    project TEXT,
    language TEXT NOT NULL DEFAULT 'C/C++',
    function_name TEXT,
    source_url TEXT,
    vuln_lines INTEGER, patch_lines INTEGER,
    vuln_chars INTEGER, patch_chars INTEGER,
    noise REAL, noise_reasoning TEXT,
    granularity TEXT,
    UNIQUE (dataset, sample_key)
);
"""

SCHEMA_TAIL = """
CREATE INDEX IF NOT EXISTS idx_samples_dataset ON samples(dataset);
CREATE INDEX IF NOT EXISTS idx_samples_language ON samples(language);
CREATE INDEX IF NOT EXISTS idx_samples_cwe ON samples(cwe);
CREATE INDEX IF NOT EXISTS idx_samples_project ON samples(project);
CREATE INDEX IF NOT EXISTS idx_samples_year ON samples(year);

CREATE TABLE IF NOT EXISTS prompts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL,
    version INTEGER NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    template TEXT NOT NULL,
    builtin INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    UNIQUE (key, version)
);

CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    options TEXT NOT NULL DEFAULT '{}',
    filters TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'pending',
    error TEXT,
    total_tasks INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT
);

CREATE TABLE IF NOT EXISTS results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    sample_id INTEGER NOT NULL REFERENCES samples(id),
    variant TEXT NOT NULL CHECK (variant IN ('vuln', 'patch')),
    prompt_id INTEGER NOT NULL REFERENCES prompts(id),
    strategy TEXT NOT NULL,
    expected INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    verdict INTEGER,
    correct INTEGER,
    parse_method TEXT,
    response TEXT,
    error TEXT,
    latency_ms INTEGER,
    input_chars INTEGER,
    truncated INTEGER NOT NULL DEFAULT 0,
    prompt_tokens INTEGER,
    completion_tokens INTEGER,
    finished_at TEXT,
    UNIQUE (run_id, sample_id, variant, strategy)
);
CREATE INDEX IF NOT EXISTS idx_results_run_status ON results(run_id, status);
CREATE INDEX IF NOT EXISTS idx_results_sample ON results(sample_id);
"""


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Database:
    def __init__(self, path: Union[str, Path]):
        self.path = str(path)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=30000")
        return conn

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        conn = self._connect()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def init(self) -> None:
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with self.tx() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(SCHEMA_HEAD + SAMPLES_DDL.format(name="samples"))
            self._migrate(conn)
            conn.executescript(SCHEMA_TAIL)

    @staticmethod
    def _migrate(conn: sqlite3.Connection) -> None:
        """Upgrade a samples table created before multi-dataset support (v0.1.0) in place."""
        cols = {r[1] for r in conn.execute("PRAGMA table_info(samples)")}
        if "dataset" in cols:
            return
        conn.execute("PRAGMA foreign_keys=OFF")
        conn.executescript(SAMPLES_DDL.format(name="samples_new"))
        conn.execute(
            "INSERT INTO samples_new (id, dataset, sample_key, commit_hash, cve, year, cwe, category, description, "
            "vulnerable_code, patched_code, num_files, num_functions, lines_added, lines_deleted, project, language, "
            "vuln_lines, patch_lines, vuln_chars, patch_chars, noise, noise_reasoning, granularity) "
            "SELECT id, 'vulnsage', commit_hash, commit_hash, cve, year, cwe, category, description, vulnerable_code, "
            "patched_code, num_files, num_functions, lines_added, lines_deleted, project, 'C/C++', vuln_lines, "
            "patch_lines, vuln_chars, patch_chars, noise, noise_reasoning, granularity FROM samples")
        conn.execute("DROP TABLE samples")
        conn.execute("ALTER TABLE samples_new RENAME TO samples")
        conn.execute("PRAGMA foreign_keys=ON")

    def q(self, sql: str, params: Sequence[Any] = ()) -> List[sqlite3.Row]:
        with self.tx() as conn:
            return conn.execute(sql, params).fetchall()

    def q1(self, sql: str, params: Sequence[Any] = ()) -> Optional[sqlite3.Row]:
        with self.tx() as conn:
            return conn.execute(sql, params).fetchone()

    def scalar(self, sql: str, params: Sequence[Any] = ()) -> Any:
        row = self.q1(sql, params)
        return None if row is None else row[0]

    def x(self, sql: str, params: Sequence[Any] = ()) -> int:
        """Execute a write and return lastrowid."""
        with self.tx() as conn:
            return conn.execute(sql, params).lastrowid

    def many(self, sql: str, rows: Iterable[Sequence[Any]]) -> None:
        with self.tx() as conn:
            conn.executemany(sql, rows)

    def get_meta(self, key: str) -> Optional[str]:
        return self.scalar("SELECT value FROM meta WHERE key=?", (key,))

    def set_meta(self, key: str, value: str) -> None:
        self.x("INSERT INTO meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))
