import time

import pytest
from fastapi.testclient import TestClient

from breachmark.app import create_app

H = {"X-BreachMark": "1"}


@pytest.fixture
def client(tmp_path):
    app = create_app(db_path=str(tmp_path / "app.db"))
    with TestClient(app) as c:
        yield c


def wait_done(client, rid, timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        p = client.get(f"/api/runs/{rid}").json()
        if p["status"] not in ("pending", "running"):
            return p
        time.sleep(0.1)
    raise AssertionError("run did not finish")


def test_health_and_pages(client):
    assert client.get("/api/health").json()["samples"] == 593
    for path in ["/", "/samples", "/samples?cwe=CWE-119&sort=year&dir=desc", "/samples/4", "/samples/4?full=1",
                 "/runs", "/runs/new", "/compare", "/playground", "/prompts", "/settings"]:
        r = client.get(path)
        assert r.status_code == 200, path
    assert client.get("/samples/99999").status_code == 404
    assert client.get("/runs/99999").status_code == 404


def test_mutations_need_header(client):
    assert client.post("/api/demo").status_code == 403
    assert client.post("/api/runs", json={}).status_code == 403
    assert client.delete("/api/runs/1").status_code == 403


def test_run_lifecycle_via_api(client):
    bad = client.post("/api/runs", json={"provider": "mock", "model": "", "strategies": ["cot"]}, headers=H)
    assert bad.status_code == 400 and "model" in bad.json()["detail"]
    r = client.post("/api/runs", json={"provider": "mock", "model": "mock-eager", "strategies": ["baseline", "cot"],
                                       "limit": 8, "options": {"concurrency": 4, "price_in": 1.0, "price_out": 2.0}},
                    headers=H)
    assert r.status_code == 200
    rid = r.json()["id"]
    p = wait_done(client, rid)
    assert p["status"] == "completed" and p["finished"] == 32
    page = client.get(f"/runs/{rid}")
    assert page.status_code == 200 and b"mock-eager" in page.content and b"$" in page.content
    assert client.get(f"/runs/{rid}/report").status_code == 200
    res = client.get(f"/api/runs/{rid}/results?strategy=cot&per_page=5").json()
    assert res["total"] == 16 and len(res["rows"]) == 5
    detail = client.get(f"/api/results/{res['rows'][0]['id']}").json()
    assert detail["strategy"] == "cot" and "VERDICT" in detail["response"] and "{code}" not in detail["prompt"]
    csv = client.get(f"/api/runs/{rid}/export.csv").text
    assert csv.startswith("run_id,") and csv.count("\n") == 33
    assert client.post(f"/api/runs/{rid}/resume", headers=H).status_code == 409
    assert client.get(f"/compare?runs={rid}").status_code == 200
    assert client.delete(f"/api/runs/{rid}", headers=H).json() == {"ok": True}
    assert client.get(f"/api/runs/{rid}").status_code == 404


def test_demo_and_compare_with_ensemble(client):
    ids = client.post("/api/demo", headers=H).json()["ids"]
    for rid in ids:
        wait_done(client, rid)
    page = client.get("/compare?runs=" + ",".join(map(str, ids)))
    assert page.status_code == 200 and b"Majority vote" in page.content
    csv = client.get("/api/compare/export.csv?runs=" + ",".join(map(str, ids))).text
    assert csv.count("\n") == 3 * 480 + 1


def test_prompts_api(client):
    prev = client.post("/api/prompts/preview", json={"template": "Look at {code}"}, headers=H).json()
    assert prev["warnings"] and "Look at" in prev["rendered"]
    bad = client.post("/api/prompts", json={"key": "x", "name": "X", "template": "no placeholder"}, headers=H)
    assert bad.status_code == 400
    ok = client.post("/api/prompts", json={"key": "think", "name": "Think", "template": "{cwe} {code} VERDICT:"}, headers=H)
    assert ok.status_code == 200
    r = client.post("/api/runs", json={"provider": "mock", "model": "mock-balanced", "strategies": ["think"], "limit": 2},
                    headers=H).json()
    wait_done(client, r["id"])
    rows = client.get(f"/api/runs/{r['id']}/results").json()["rows"]
    assert rows[0]["strategy"] == "think@v2"


def test_playground_and_providers(client):
    r = client.post("/api/playground", json={"provider": "mock", "model": "mock-eager", "strategies": ["baseline"],
                                             "code": "strcpy(a, b);", "cwe": "119"}, headers=H).json()
    assert r["cwe"] == "CWE-119" and r["results"][0]["verdict_text"] in ("YES", "NO")
    empty = client.post("/api/playground", json={"provider": "mock", "model": "m", "strategies": ["baseline"], "code": ""}, headers=H)
    assert empty.status_code == 400
    assert client.post("/api/playground/commit", json={"url": "https://example.com"}, headers=H).status_code == 400
    ping = client.post("/api/providers/mock/ping", json={}, headers=H).json()
    assert ping["ok"] and "mock-eager" in ping["models"]
    assert client.post("/api/providers/nope/ping", json={}, headers=H).status_code == 404
    assert client.post("/api/providers/openai/key", json={"key": "sk-1"}, headers=H).json()["key_source"] == "session"
    assert client.post("/api/providers/openai/key", json={"key": ""}, headers=H).json()["key_source"] == "missing"


def test_blind_mode_hides_cwe(client):
    normal = client.post("/api/runs", json={"provider": "mock", "model": "mock-balanced", "strategies": ["cot"],
                                            "limit": 3, "shuffle_seed": 1}, headers=H).json()["id"]
    blind = client.post("/api/runs", json={"provider": "mock", "model": "mock-balanced", "strategies": ["cot"],
                                           "limit": 3, "shuffle_seed": 1, "options": {"blind": True}}, headers=H).json()["id"]
    wait_done(client, normal)
    wait_done(client, blind)
    p_normal = client.get(f"/api/results/{client.get(f'/api/runs/{normal}/results').json()['rows'][0]['id']}").json()["prompt"]
    p_blind = client.get(f"/api/results/{client.get(f'/api/runs/{blind}/results').json()['rows'][0]['id']}").json()["prompt"]
    assert "CWE-" in p_normal
    assert "CWE-" not in p_blind and "any security vulnerability" in p_blind
    page = client.get(f"/runs/{blind}")
    assert b"blind" in page.content
    assert b"blind: no CWE hint" not in client.get(f"/runs/{normal}").content
