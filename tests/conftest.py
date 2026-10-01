import asyncio
from pathlib import Path

import pytest

from breachmark import runner
from breachmark.db import Database
from breachmark.importer import import_dataset, import_sven
from breachmark.prompts import seed_prompts

DATASET = Path(__file__).resolve().parent.parent / "data" / "vulnerabilities.csv"


@pytest.fixture(autouse=True)
def fast_retries(monkeypatch):
    monkeypatch.setattr(runner, "RETRY_BASE_DELAY", 0)


@pytest.fixture
def db(tmp_path):
    database = Database(tmp_path / "test.db")
    database.init()
    seed_prompts(database)
    import_dataset(database, DATASET)
    import_sven(database, DATASET.parent / "sven")
    return database


@pytest.fixture
def manager(db):
    return runner.RunManager(db)


def run_to_end(manager, run_id):
    async def go():
        await manager.start(run_id)
        await manager.wait(run_id)
    asyncio.run(go())
