import asyncio
from pathlib import Path

import pytest

from breachmark import analytics, parsing, prompts, queries, runs
from breachmark.db import Database
from breachmark.importer import granularity, import_dataset
from breachmark.providers import ProviderError
from breachmark.providers.mock import MockProvider

from conftest import DATASET, run_to_end


# ---------------- importer ----------------
def test_import_is_idempotent(db):
    assert db.scalar("SELECT COUNT(*) FROM samples") == 593
    second = import_dataset(db, DATASET)
    assert second == {"rows": 593, "inserted": 0, "updated": 593, "skipped": 0, "total": 593}
    assert db.scalar("SELECT COUNT(DISTINCT cwe) FROM samples") == 52
    assert db.scalar("SELECT COUNT(DISTINCT cve) FROM samples") == 491
    assert db.scalar("SELECT COUNT(*) FROM samples WHERE vuln_lines < 1") == 0


def test_import_rejects_bad_csv(tmp_path):
    bad = tmp_path / "bad.csv"
    bad.write_text("id,COMMIT_HASH\n1,abc\n")
    database = Database(tmp_path / "x.db")
    database.init()
    with pytest.raises(ValueError, match="missing required columns"):
        import_dataset(database, bad)


def test_granularity_buckets():
    assert granularity(1, 1) == "G1"
    assert granularity(1, 5) == "G2"
    assert granularity(3, 5) == "G3"
    assert granularity(1, 0) == "G3"


# ---------------- queries ----------------
def test_filters_and_selection(db):
    assert queries.count_samples(db, {"cwe": "CWE-119"}) == 58
    assert queries.count_samples(db, {"project": "xen", "max_noise": 0}) == 18
    # LIKE wildcards are escaped: "%" and "_" match only literal characters
    literal = db.scalar("SELECT COUNT(*) FROM samples WHERE instr(cve,'%')>0 OR instr(commit_hash,'%')>0 "
                        "OR instr(description,'%')>0 OR instr(category,'%')>0 OR instr(cwe,'%')>0")
    assert queries.count_samples(db, {"q": "%"}) == literal < 593
    assert queries.count_samples(db, {"q": "_"}) < 593
    a = queries.select_sample_ids(db, {}, limit=10, seed=3)
    b = queries.select_sample_ids(db, {}, limit=10, seed=3)
    assert a == b and len(a) == 10
    assert queries.select_sample_ids(db, {}, limit=10, seed=4) != a


# ---------------- prompts & parsing ----------------
def test_render_is_brace_safe():
    out = prompts.render_prompt("Find {cwe}:\n{code}", 'printf("{code} {cwe}");', "CWE-134")
    assert out == 'Find CWE-134:\nprintf("{code} {cwe}");'
    assert "any security vulnerability" in prompts.render_prompt("{cwe} {code}", "x", None)


def test_input_policies():
    code = "a" * 1000 + "\n" + "b" * 1000
    short, truncated, skipped = prompts.apply_input_policy(code, 500, "truncate")
    assert truncated and not skipped and len(short) < 700 and "omitted by BreachMark" in short
    assert short.startswith("a") and short.endswith("b")
    assert prompts.apply_input_policy(code, 500, "skip") == (code, False, True)
    assert prompts.apply_input_policy(code, 500, "none") == (code, False, False)
    assert prompts.apply_input_policy(code, 0, "truncate") == (code, False, False)


def test_prompt_versioning(db):
    first = prompts.latest_prompt_ids(db, ["cot"])[0]
    new_id = prompts.save_prompt_version(db, "cot", "Chain of thought", "x {code} {cwe}")
    assert prompts.latest_prompt_ids(db, ["cot"])[0] == new_id != first
    assert db.scalar("SELECT version FROM prompts WHERE id=?", (new_id,)) == 2
    with pytest.raises(ValueError):
        prompts.save_prompt_version(db, "nocode", "No code", "missing placeholder")
    with pytest.raises(ValueError):
        prompts.latest_prompt_ids(db, ["does_not_exist"])


@pytest.mark.parametrize("text,expected,method", [
    ("VERDICT: YES", 1, "verdict"),
    ("...lots of analysis...\nVERDICT: NO\n", 0, "verdict"),
    ("**VERDICT:** YES", 1, "verdict"),
    ("Verdict: no.", 0, "verdict"),
    ("VERDICT: <YES or NO>", 2, "none"),           # echoing the instruction is not an answer
    ("VERDICT: YES or NO", 2, "none"),
    ("Final Decision: YES", 1, "final"),
    ("Final answer - NO", 0, "final"),
    ("CWE-119 present: yes", 1, "label"),
    ("<think>I think YES... actually VERDICT: YES</think>\nVERDICT: NO", 0, "verdict"),  # think block ignored
    ("<think>never closed, model ran out of tokens", 2, "none"),
    ("VERDICT: YES\n\nWait. VERDICT: NO", 0, "verdict"),  # last one wins
    ("", 2, "none"),
])
def test_parse_verdict(text, expected, method):
    assert parsing.parse_verdict(text) == (expected, method)


def test_parse_bare_only_when_allowed():
    assert parsing.parse_verdict("YES", allow_bare=False) == (2, "none")
    assert parsing.parse_verdict("**No**", allow_bare=True) == (0, "bare")
    assert parsing.parse_verdict("Yes.\nThis is vulnerable because...", allow_bare=True) == (1, "bare")
    assert parsing.parse_verdict("x" * 300 + " yes", allow_bare=True) == (2, "none")


def test_parse_judge():
    assert parsing.parse_judge("YES") == 1
    assert parsing.parse_judge("The answer is NO.") == 0
    assert parsing.parse_judge("UNCLEAR") == 2
    assert parsing.parse_judge("") == 2


# ---------------- runs & runner ----------------
def test_run_options_validation(db):
    base = {"provider": "mock", "model": "m", "strategies": ["baseline"]}
    with pytest.raises(ValueError, match="model"):
        runs.create_run(db, {**base, "model": ""})
    with pytest.raises(ValueError, match="strategy"):
        runs.create_run(db, {**base, "strategies": []})
    with pytest.raises(ValueError, match="No samples"):
        runs.create_run(db, {**base, "filters": {"cwe": "CWE-0"}})
    with pytest.raises(ValueError, match="temperature"):
        runs.create_run(db, {**base, "options": {"temperature": 9}})
    with pytest.raises(ValueError, match="Base URL"):
        runs.create_run(db, {**base, "options": {"base_url": "localhost:11434"}})
    est = runs.estimate(db, {**base, "limit": 7, "strategies": ["baseline", "cot"]})
    assert est["samples"] == 7 and est["requests"] == 28


def test_complete_run_and_metrics(db, manager):
    rid = runs.create_run(db, {"provider": "mock", "model": "mock-eager", "strategies": ["baseline", "cot"],
                               "limit": 20, "shuffle_seed": 1, "options": {"concurrency": 4}})
    assert runs.run_progress(db, rid)["total"] == 80
    run_to_end(manager, rid)
    p = runs.run_progress(db, rid)
    assert p["status"] == "completed" and p["counts"] == {"pending": 0, "done": 80, "error": 0, "skipped": 0}
    m = analytics.metrics_by_strategy(db, rid)
    assert set(m) == {"baseline", "cot"}
    for s in m.values():
        assert s["n"] == 40 and s["n_vuln"] == 20 and s["n_patch"] == 20
        assert 0 <= s["accuracy"] <= 1 and s["acc_lo"] <= s["accuracy"] <= s["acc_hi"]
        c = s["confusion"]
        assert c["vuln"]["yes"] + c["vuln"]["no"] + c["vuln"]["amb"] == 20
    row = db.q1("SELECT parse_method, latency_ms, prompt_tokens FROM results WHERE run_id=? AND strategy='cot'", (rid,))
    assert row["parse_method"] == "verdict" and row["latency_ms"] >= 0 and row["prompt_tokens"] > 0


def test_retries_recover_from_transient_errors(db, manager):
    rid = runs.create_run(db, {"provider": "mock", "model": "mock-flaky", "strategies": ["cot"], "limit": 20,
                               "options": {"concurrency": 4}})
    run_to_end(manager, rid)
    assert runs.run_progress(db, rid)["counts"]["error"] == 0


def test_circuit_breaker_stops_broken_runs(db, manager):
    rid = runs.create_run(db, {"provider": "mock", "model": "mock-broken", "strategies": ["cot"], "limit": 40,
                               "options": {"concurrency": 1}})
    run_to_end(manager, rid)
    run = runs.get_run(db, rid)
    assert run["status"] == "failed" and "failures in a row" in run["error"]
    assert runs.run_progress(db, rid)["counts"]["error"] == 10
    # with parallel workers the stop is still prompt: a few in-flight tasks may fail after the trip
    rid_par = runs.create_run(db, {"provider": "mock", "model": "mock-broken", "strategies": ["cot"], "limit": 40,
                                   "options": {"concurrency": 4}})
    run_to_end(manager, rid_par)
    assert 10 <= runs.run_progress(db, rid_par)["counts"]["error"] <= 14
    # retry-errors resets the failed rows so the run can be resumed
    assert runs.reset_errors(db, rid) == 10
    assert runs.get_run(db, rid)["status"] == "paused"


def test_pause_resume_cancel(db, manager):
    rid = runs.create_run(db, {"provider": "mock", "model": "mock-balanced", "strategies": ["think"], "limit": 60,
                               "options": {"concurrency": 2}})

    async def pause_then_resume():
        await manager.start(rid)
        await asyncio.sleep(0.15)
        assert manager.pause(rid)
        await manager.wait(rid)
        p = runs.run_progress(db, rid)
        assert p["status"] == "paused" and 0 < p["finished"] < p["total"]
        await manager.start(rid)
        await manager.wait(rid)
        assert runs.run_progress(db, rid)["status"] == "completed"
    asyncio.run(pause_then_resume())

    rid2 = runs.create_run(db, {"provider": "mock", "model": "mock-balanced", "strategies": ["think"], "limit": 60})

    async def cancel():
        await manager.start(rid2)
        await asyncio.sleep(0.1)
        assert manager.cancel(rid2)
        await manager.wait(rid2)
    asyncio.run(cancel())
    assert runs.get_run(db, rid2)["status"] == "cancelled"


def test_skip_policy_and_truncation_flag(db, manager):
    rid = runs.create_run(db, {"provider": "mock", "model": "mock-balanced", "strategies": ["baseline"], "limit": 40,
                               "options": {"max_input_chars": 3000, "input_policy": "skip"}})
    run_to_end(manager, rid)
    counts = runs.run_progress(db, rid)["counts"]
    assert counts["skipped"] > 0 and counts["done"] + counts["skipped"] == 80
    rid2 = runs.create_run(db, {"provider": "mock", "model": "mock-balanced", "strategies": ["baseline"], "limit": 40,
                                "options": {"max_input_chars": 3000, "input_policy": "truncate"}})
    run_to_end(manager, rid2)
    assert db.scalar("SELECT COUNT(*) FROM results WHERE run_id=? AND truncated=1", (rid2,)) > 0


def test_judge_rescues_garbled_answers(db, manager):
    spec = {"provider": "mock", "model": "mock-garbled", "strategies": ["cot"], "limit": 10}
    rid = runs.create_run(db, spec)
    run_to_end(manager, rid)
    assert analytics.metrics_by_strategy(db, rid)["cot"]["ambiguous_rate"] == 1.0
    rid2 = runs.create_run(db, {**spec, "options": {"judge": True, "judge_model": "mock-eager"}})
    run_to_end(manager, rid2)
    assert analytics.metrics_by_strategy(db, rid2)["cot"]["ambiguous_rate"] < 1.0
    assert db.scalar("SELECT COUNT(*) FROM results WHERE run_id=? AND parse_method='judge'", (rid2,)) > 0


def test_recover_interrupted_marks_runs_paused(db, manager):
    rid = runs.create_run(db, {"provider": "mock", "model": "m", "strategies": ["baseline"], "limit": 2})
    db.x("UPDATE runs SET status='running' WHERE id=?", (rid,))
    assert manager.recover_interrupted() == 1
    assert runs.get_run(db, rid)["status"] == "paused"


# ---------------- analytics ----------------
def _row(sample, variant, verdict, strategy="cot", run_id=1, **extra):
    expected = 1 if variant == "vuln" else 0
    return {"run_id": run_id, "sample_id": sample, "strategy": strategy, "variant": variant, "expected": expected,
            "status": "done", "verdict": verdict, "correct": 1 if verdict == expected else 0, "latency_ms": 10,
            "prompt_tokens": 5, "completion_tokens": 5, "truncated": 0, "cwe": "CWE-1", "project": "p", "year": 2010,
            "noise": 0, "granularity": "G1", **extra}


def test_compute_metrics_by_hand():
    rows = [_row(1, "vuln", 1), _row(1, "patch", 0),   # perfect pair
            _row(2, "vuln", 0), _row(2, "patch", 1),   # both wrong
            _row(3, "vuln", 2), _row(3, "patch", 0)]   # ambiguous + right
    m = analytics.compute_metrics(rows)
    assert m["n"] == 6 and m["accuracy"] == pytest.approx(3 / 6)
    assert m["tpr"] == pytest.approx(1 / 3) and m["tnr"] == pytest.approx(2 / 3)
    assert m["precision"] == pytest.approx(1 / 2) and m["ambiguous_rate"] == pytest.approx(1 / 6)
    assert m["pair_n"] == 3 and m["pair_correct"] == pytest.approx(1 / 3)
    assert m["confusion"] == {"vuln": {"yes": 1, "no": 1, "amb": 1}, "patch": {"yes": 1, "no": 2, "amb": 0}}


def test_wilson_interval():
    lo, hi = analytics.wilson(50, 100)
    assert 0.40 < lo < 0.5 < hi < 0.60
    assert analytics.wilson(0, 0) == (None, None)


def test_ensemble_majority_vote():
    rows = [_row(1, "vuln", 1, run_id=1), _row(1, "vuln", 1, run_id=2), _row(1, "vuln", 0, run_id=3),
            _row(2, "vuln", 1, run_id=1), _row(2, "vuln", 0, run_id=2),           # tie -> ambiguous
            _row(3, "vuln", 1, run_id=1, strategy="think")]                        # other strategy ignored
    out = {r["sample_id"]: r["verdict"] for r in analytics.ensemble_rows(rows, "cot")}
    assert out == {1: 1, 2: 2}


def test_breakdown_and_heatmap():
    rows = [_row(1, "vuln", 1, noise=0), _row(2, "vuln", 0, noise=60), _row(3, "vuln", 1, noise=None, cwe="CWE-2")]
    b = {x["label"]: x["accuracy"] for x in analytics.breakdown(rows, "noise")}
    assert b == {"0%": 1.0, "51%+": 0.0, "unknown": 1.0}
    h = analytics.cwe_heatmap(rows)
    assert h["strategies"] == ["cot"] and [r["cwe"] for r in h["rows"]] == ["CWE-1", "CWE-2"]


# ---------------- providers ----------------
def test_mock_provider_is_deterministic():
    async def go():
        m = MockProvider()
        a = await m.generate("Answer with exactly one word", "mock-eager")
        b = await m.generate("Answer with exactly one word", "mock-eager")
        assert a.text == b.text in ("YES", "NO")
        with pytest.raises(ProviderError):
            await m.generate("x", "mock-broken")
    asyncio.run(go())
