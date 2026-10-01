"""FastAPI application: pages and JSON API."""
from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import Any, Callable, Dict, List, Optional

from fastapi import Body, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.trustedhost import TrustedHostMiddleware

from . import __version__, analytics, config, queries, runs as runs_mod
from .db import Database
from .diffview import diff_rows
from .importer import ensure_dataset, import_dataset
from .playground import fetch_commit_diff, run_playground
from .prompts import render_prompt, save_prompt_version, seed_prompts, validate_template
from .providers import PROVIDER_CLASSES, make_provider, provider_info
from .runner import RunManager
from .export import results_csv

MUTATING = {"POST", "PUT", "PATCH", "DELETE"}
VARIANT_LABEL = {"vuln": "Vulnerable code", "patch": "Patched code"}


# ---------- template filters ----------
def f_pct(value: Optional[float], digits: int = 1) -> str:
    return "n/a" if value is None else f"{value * 100:.{digits}f}%"


def f_num(value: Any) -> str:
    return "n/a" if value is None else f"{int(value):,}"


def f_dt(value: Optional[str]) -> str:
    return "" if not value else value.replace("T", " ").replace("Z", " UTC")[:19] + ("" if len(value) < 20 else " UTC")


def f_ms(value: Optional[float]) -> str:
    if value is None:
        return "n/a"
    return f"{value:.0f} ms" if value < 1000 else f"{value / 1000:.1f} s"


def f_tok(value: Optional[int]) -> str:
    if not value:
        return "0"
    return f"{value / 1e6:.2f}M" if value >= 1e6 else f"{value / 1e3:.1f}k" if value >= 1e3 else str(value)


def f_eta(seconds: Optional[int]) -> str:
    if seconds is None:
        return ""
    if seconds < 90:
        return f"{seconds}s"
    if seconds < 5400:
        return f"{seconds // 60}m"
    return f"{seconds / 3600:.1f}h"


def create_app(db_path: Optional[str] = None, provider_factory: Optional[Callable[..., Any]] = None,
               auto_import: bool = True) -> FastAPI:
    settings = config.get_settings()
    db = Database(db_path or settings.db_path)
    db.init()
    seed_prompts(db)
    if auto_import:
        ensure_dataset(db, settings.dataset_path)
    manager = RunManager(db, provider_factory or make_provider)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        manager.recover_interrupted()
        yield
        await manager.shutdown()

    app = FastAPI(title="BreachMark", version=__version__, lifespan=lifespan, docs_url="/api/docs", redoc_url=None)
    app.state.db = db
    app.state.manager = manager
    app.state.settings = settings

    hosts = [h.strip() for h in os.environ.get("BREACHMARK_ALLOWED_HOSTS", "").split(",") if h.strip()]
    if not hosts:
        # Bound to loopback: only accept local host names (blocks DNS rebinding). Bound to a network
        # interface on purpose: accept any host name, since the user chose to expose the app.
        local = settings.host in ("127.0.0.1", "localhost", "::1")
        hosts = ["localhost", "127.0.0.1", "[::1]", "testserver"] if local else ["*"]
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=hosts)
    app.mount("/static", StaticFiles(directory=str(config.PACKAGE_DIR / "static")), name="static")

    templates = Jinja2Templates(directory=str(config.PACKAGE_DIR / "templates"))
    templates.env.filters.update(pct=f_pct, num=f_num, dt=f_dt, ms=f_ms, tok=f_tok, eta=f_eta)
    templates.env.globals.update(version=__version__, variant_label=VARIANT_LABEL)

    def page(request: Request, name: str, active: str, **ctx: Any) -> HTMLResponse:
        return templates.TemplateResponse(request, name, {"active": active, **ctx})

    @app.middleware("http")
    async def require_header(request: Request, call_next):
        # Mutating requests must come from our own JS (or a deliberate API client), not from another website.
        if request.method in MUTATING and request.url.path.startswith("/api") and "x-breachmark" not in request.headers:
            return JSONResponse({"detail": "Missing X-BreachMark header."}, status_code=403)
        return await call_next(request)

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException):
        if request.url.path.startswith("/api"):
            return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
        return templates.TemplateResponse(request, "error.html", {"active": "", "code": exc.status_code,
                                                                   "message": exc.detail}, status_code=exc.status_code)

    def bad(msg: str, code: int = 400) -> HTTPException:
        return HTTPException(code, msg)

    def parse_ids(text: str) -> List[int]:
        out = []
        for part in (text or "").split(","):
            if part.strip().isdigit():
                out.append(int(part))
        return out

    # =====================================================================================
    # Pages
    # =====================================================================================
    @app.get("/", response_class=HTMLResponse)
    def dashboard(request: Request):
        stats = queries.facets(db)
        run_list = runs_mod.list_runs(db)
        recent = []
        for r in run_list[:6]:
            recent.append({**r, "progress": runs_mod.run_progress(db, r["id"])})
        board = analytics.leaderboard(db)[:6]
        n_done = db.scalar("SELECT COUNT(*) FROM results WHERE status='done'") or 0
        return page(request, "dashboard.html", "dashboard", stats=stats, runs_total=len(run_list), recent=recent,
                    board=board, n_done=n_done, providers=provider_info())

    @app.get("/samples", response_class=HTMLResponse)
    def samples_page(request: Request, q: str = "", cwe: str = "", project: str = "", granularity: str = "",
                     year_min: str = "", year_max: str = "", max_noise: str = "", page_no: int = 1, sort: str = "id",
                     dir: str = "asc"):
        filters = {"q": q, "cwe": cwe, "project": project, "granularity": granularity, "year_min": year_min,
                   "year_max": year_max, "max_noise": max_noise}
        result = queries.list_samples(db, filters, page=page_no, sort=sort, direction=dir)
        return page(request, "samples.html", "samples", filters=filters, result=result, facets=queries.facets(db),
                    sort=sort, dir=dir)

    @app.get("/samples/{sid}", response_class=HTMLResponse)
    def sample_page(request: Request, sid: int, full: int = 0):
        s = db.q1("SELECT * FROM samples WHERE id=?", (sid,))
        if s is None:
            raise HTTPException(404, "Sample not found.")
        diff = diff_rows(s["vulnerable_code"], s["patched_code"], full=bool(full), max_rows=30000 if full else 6000)
        results = db.q(
            "SELECT r.id, r.run_id, u.name AS run_name, u.model, u.provider, r.strategy, r.variant, r.status, "
            "r.verdict, r.correct FROM results r JOIN runs u ON u.id=r.run_id WHERE r.sample_id=? AND r.status!='pending' "
            "ORDER BY r.run_id DESC, r.strategy, r.variant", (sid,))
        prev_id = db.scalar("SELECT MAX(id) FROM samples WHERE id<?", (sid,))
        next_id = db.scalar("SELECT MIN(id) FROM samples WHERE id>?", (sid,))
        view = {k: s[k] for k in s.keys() if k not in ("vulnerable_code", "patched_code")}
        return page(request, "sample.html", "samples", s=view, diff=diff, full=bool(full), results=results,
                    vuln_code=s["vulnerable_code"][:200_000], patch_code=s["patched_code"][:200_000],
                    code_cut=max(len(s["vulnerable_code"]), len(s["patched_code"])) > 200_000,
                    prev_id=prev_id, next_id=next_id)

    @app.get("/runs", response_class=HTMLResponse)
    def runs_page(request: Request):
        items = [{**r, "progress": runs_mod.run_progress(db, r["id"])} for r in runs_mod.list_runs(db)]
        return page(request, "runs.html", "runs", items=items)

    @app.get("/runs/new", response_class=HTMLResponse)
    def run_new(request: Request):
        prompts = db.q("SELECT p.id, p.key, p.version, p.name, p.description FROM prompts p "
                       "WHERE p.version=(SELECT MAX(version) FROM prompts WHERE key=p.key) ORDER BY p.builtin DESC, p.key")
        return page(request, "run_new.html", "runs", prompts=prompts, facets=queries.facets(db),
                    providers=provider_info(), defaults=runs_mod.DEFAULT_OPTIONS)

    @app.get("/runs/{rid}", response_class=HTMLResponse)
    def run_page(request: Request, rid: int, strategy: str = ""):
        run = runs_mod.get_run(db, rid)
        if run is None:
            raise HTTPException(404, "Run not found.")
        progress = runs_mod.run_progress(db, rid)
        by_strategy = analytics.metrics_by_strategy(db, rid)
        strategies = list(by_strategy)
        focus = strategy if strategy in by_strategy else (strategies[0] if strategies else "")
        rows = [r for r in analytics.fetch_rows(db, [rid])]
        focus_rows = [r for r in rows if r["strategy"] == focus]
        costs = {s: analytics.cost_estimate(run, m) for s, m in by_strategy.items()}
        return page(request, "run.html", "runs", run=run, progress=progress, by_strategy=by_strategy,
                    strategies=strategies, focus=focus, costs=costs,
                    heatmap=analytics.cwe_heatmap(rows), breakdowns={
                        "Project": analytics.breakdown(focus_rows, "project"),
                        "Granularity": analytics.breakdown(focus_rows, "granularity"),
                        "Noise in dataset label": analytics.breakdown(focus_rows, "noise"),
                        "Year": analytics.breakdown(focus_rows, "year")},
                    active_run=manager.is_active(rid))

    @app.get("/runs/{rid}/report", response_class=HTMLResponse)
    def run_report(request: Request, rid: int, download: int = 0):
        run = runs_mod.get_run(db, rid)
        if run is None:
            raise HTTPException(404, "Run not found.")
        by_strategy = analytics.metrics_by_strategy(db, rid)
        rows = analytics.fetch_rows(db, [rid])
        response = templates.TemplateResponse(request, "report.html", {
            "run": run, "progress": runs_mod.run_progress(db, rid), "by_strategy": by_strategy,
            "heatmap": analytics.cwe_heatmap(rows),
            "projects": {s: analytics.breakdown([r for r in rows if r["strategy"] == s], "project") for s in by_strategy}})
        if download:
            response.headers["Content-Disposition"] = f'attachment; filename="breachmark-run-{rid}.html"'
        return response

    @app.get("/compare", response_class=HTMLResponse)
    def compare_page(request: Request, runs: str = "", focus: int = 0, strategy: str = ""):
        all_runs = runs_mod.list_runs(db)
        known = {r["id"] for r in all_runs}
        selected = [i for i in parse_ids(runs) if i in known]
        rows = analytics.fetch_rows(db, selected) if selected else []
        board = analytics.leaderboard(db, selected) if selected else []
        focus_id = focus if focus in selected else (selected[0] if selected else 0)
        focus_rows = [r for r in rows if r["run_id"] == focus_id]
        focus_strats = sorted({r["strategy"] for r in focus_rows})
        strat = strategy if strategy in focus_strats else (focus_strats[0] if focus_strats else "")
        strat_rows = [r for r in focus_rows if r["strategy"] == strat]
        per_strategy_runs: Dict[str, set] = {}
        for r in rows:
            per_strategy_runs.setdefault(r["strategy"], set()).add(r["run_id"])
        ensembles = []
        for s, rids in sorted(per_strategy_runs.items()):
            if len(rids) >= 2:
                m = analytics.compute_metrics(analytics.ensemble_rows(rows, s))
                best = max((e for e in board if e["strategy"] == s), key=lambda e: e["accuracy"] or 0)
                ensembles.append({"strategy": s, "voters": len(rids), "metrics": m, "best": best})
        return page(request, "compare.html", "compare", all_runs=all_runs, selected=selected, board=board,
                    focus_id=focus_id, focus_strats=focus_strats, strat=strat, ensembles=ensembles,
                    heatmap=analytics.cwe_heatmap(focus_rows) if focus_rows else None,
                    confusion={e["strategy"]: e["confusion"] for e in board if e["run_id"] == focus_id},
                    breakdowns={"Project": analytics.breakdown(strat_rows, "project"),
                                "Granularity": analytics.breakdown(strat_rows, "granularity"),
                                "Noise in dataset label": analytics.breakdown(strat_rows, "noise"),
                                "Year": analytics.breakdown(strat_rows, "year")} if strat_rows else {})

    @app.get("/playground", response_class=HTMLResponse)
    def playground_page(request: Request):
        prompts = db.q("SELECT p.id, p.key, p.version, p.name FROM prompts p WHERE p.version="
                       "(SELECT MAX(version) FROM prompts WHERE key=p.key) ORDER BY p.builtin DESC, p.key")
        return page(request, "playground.html", "playground", prompts=prompts, providers=provider_info(),
                    defaults=runs_mod.DEFAULT_OPTIONS)

    @app.get("/prompts", response_class=HTMLResponse)
    def prompts_page(request: Request):
        rows = db.q("SELECT * FROM prompts ORDER BY key, version DESC")
        groups: Dict[str, List[Any]] = {}
        for r in rows:
            groups.setdefault(r["key"], []).append(r)
        return page(request, "prompts.html", "prompts", groups=groups)

    @app.get("/settings", response_class=HTMLResponse)
    def settings_page(request: Request):
        return page(request, "settings.html", "settings", providers=provider_info(), settings=settings,
                    sample_count=db.scalar("SELECT COUNT(*) FROM samples") or 0,
                    dataset_path=db.get_meta("dataset_path") or str(settings.dataset_path or ""),
                    db_path=db.path)

    # =====================================================================================
    # JSON API
    # =====================================================================================
    @app.get("/api/health")
    def health():
        return {"ok": True, "version": __version__, "samples": db.scalar("SELECT COUNT(*) FROM samples")}

    @app.get("/api/providers")
    def api_providers():
        return provider_info()

    @app.post("/api/providers/{name}/ping")
    async def api_ping(name: str, body: Dict[str, Any] = Body(default={})):
        if name not in PROVIDER_CLASSES:
            raise bad("Unknown provider.", 404)
        base = (body.get("base_url") or "").strip() or None
        if base and not base.lower().startswith(("http://", "https://")):
            raise bad("Base URL must start with http:// or https://")
        provider = manager.provider_factory(name, base_url=base, timeout=15.0)
        try:
            result = await provider.ping()
        finally:
            await provider.aclose()
        result["base_url"] = provider.base_url
        return result

    @app.post("/api/providers/{name}/key")
    def api_key(name: str, body: Dict[str, Any] = Body(...)):
        if name not in config.KEY_ENV_VARS:
            raise bad("This provider does not use an API key.", 404)
        config.set_session_key(name, body.get("key") or "")
        return {"ok": True, "key_source": config.key_source(name)}

    def spec_from(body: Dict[str, Any]) -> Dict[str, Any]:
        return {k: body.get(k) for k in ("name", "provider", "model", "strategies", "prompt_ids", "variants", "filters",
                                         "limit", "shuffle_seed", "options")}

    @app.post("/api/estimate")
    def api_estimate(body: Dict[str, Any] = Body(...)):
        try:
            return runs_mod.estimate(db, spec_from(body))
        except ValueError as exc:
            raise bad(str(exc))

    @app.post("/api/runs")
    async def api_create_run(body: Dict[str, Any] = Body(...)):
        try:
            rid = runs_mod.create_run(db, spec_from(body))
        except ValueError as exc:
            raise bad(str(exc))
        await manager.start(rid)
        return {"id": rid}

    @app.get("/api/runs/{rid}")
    def api_run(rid: int):
        progress = runs_mod.run_progress(db, rid)
        if progress is None:
            raise bad("Run not found.", 404)
        progress["active"] = manager.is_active(rid)
        return progress

    @app.post("/api/runs/{rid}/{action}")
    async def api_run_action(rid: int, action: str):
        run = runs_mod.get_run(db, rid)
        if run is None:
            raise bad("Run not found.", 404)
        if action == "pause":
            return {"ok": manager.pause(rid)}
        if action == "cancel":
            return {"ok": manager.cancel(rid)}
        if action in ("resume", "retry-errors"):
            if manager.is_active(rid):
                raise bad("This run is already running.", 409)
            reset = runs_mod.reset_errors(db, rid) if action == "retry-errors" else 0
            if db.scalar("SELECT COUNT(*) FROM results WHERE run_id=? AND status='pending'", (rid,)) == 0:
                raise bad("Nothing left to do: no pending or failed tasks.", 409)
            await manager.start(rid)
            return {"ok": True, "reset": reset}
        raise bad("Unknown action.", 404)

    @app.delete("/api/runs/{rid}")
    def api_delete_run(rid: int):
        if manager.is_active(rid):
            raise bad("Pause or cancel the run before deleting it.", 409)
        if runs_mod.get_run(db, rid) is None:
            raise bad("Run not found.", 404)
        runs_mod.delete_run(db, rid)
        return {"ok": True}

    @app.get("/api/runs/{rid}/results")
    def api_results(rid: int, strategy: str = "", variant: str = "", outcome: str = "", page_no: int = 1, per_page: int = 25):
        clauses, params = ["r.run_id=?", "r.status!='pending'"], [rid]
        if strategy:
            clauses.append("r.strategy=?"); params.append(strategy)
        if variant in ("vuln", "patch"):
            clauses.append("r.variant=?"); params.append(variant)
        if outcome == "correct":
            clauses.append("r.status='done' AND r.correct=1")
        elif outcome == "wrong":
            clauses.append("r.status='done' AND r.correct=0 AND r.verdict!=2")
        elif outcome == "ambiguous":
            clauses.append("r.status='done' AND r.verdict=2")
        elif outcome in ("error", "skipped"):
            clauses.append("r.status=?"); params.append(outcome)
        where = " AND ".join(clauses)
        total = db.scalar(f"SELECT COUNT(*) FROM results r WHERE {where}", params) or 0
        per_page = max(1, min(per_page, 100))
        rows = db.q(
            f"SELECT r.id, r.sample_id, s.cve, s.cwe, s.project, r.strategy, r.variant, r.status, r.verdict, r.correct, "
            f"r.parse_method, r.latency_ms, r.truncated, r.error FROM results r JOIN samples s ON s.id=r.sample_id "
            f"WHERE {where} ORDER BY r.id LIMIT ? OFFSET ?", params + [per_page, (max(1, page_no) - 1) * per_page])
        return {"total": total, "page": page_no, "pages": max(1, -(-total // per_page)), "rows": [dict(r) for r in rows]}

    @app.get("/api/results/{result_id}")
    def api_result(result_id: int):
        r = db.q1("SELECT r.*, u.model, u.provider, u.options, s.cwe, s.project, s.category, s.cve, "
                  "CASE WHEN r.variant='vuln' THEN s.vulnerable_code ELSE s.patched_code END AS code, p.template "
                  "FROM results r JOIN runs u ON u.id=r.run_id JOIN samples s ON s.id=r.sample_id "
                  "JOIN prompts p ON p.id=r.prompt_id WHERE r.id=?", (result_id,))
        if r is None:
            raise bad("Result not found.", 404)
        import json as _json
        from .prompts import apply_input_policy
        opts = _json.loads(r["options"] or "{}")
        code, _, _ = apply_input_policy(r["code"], opts.get("max_input_chars"), opts.get("input_policy", "truncate"))
        prompt = render_prompt(r["template"], code, None if opts.get("blind") else r["cwe"], r["project"] or "", r["category"] or "")
        return {"id": r["id"], "cve": r["cve"], "cwe": r["cwe"], "model": r["model"], "strategy": r["strategy"],
                "variant": r["variant"], "expected": r["expected"], "verdict": r["verdict"], "correct": r["correct"],
                "status": r["status"], "parse_method": r["parse_method"], "error": r["error"], "response": r["response"],
                "latency_ms": r["latency_ms"], "prompt_tokens": r["prompt_tokens"],
                "completion_tokens": r["completion_tokens"], "prompt": prompt[:60000],
                "prompt_cut": len(prompt) > 60000}

    @app.get("/api/runs/{rid}/export.csv")
    def api_export_run(rid: int, include_response: int = 0):
        if runs_mod.get_run(db, rid) is None:
            raise bad("Run not found.", 404)
        return StreamingResponse(results_csv(db, [rid], bool(include_response)), media_type="text/csv",
                                 headers={"Content-Disposition": f'attachment; filename="breachmark-run-{rid}.csv"'})

    @app.get("/api/compare/export.csv")
    def api_export_compare(runs: str = "", include_response: int = 0):
        ids = [i for i in parse_ids(runs) if runs_mod.get_run(db, i)]
        if not ids:
            raise bad("Select at least one run.")
        return StreamingResponse(results_csv(db, ids, bool(include_response)), media_type="text/csv",
                                 headers={"Content-Disposition": 'attachment; filename="breachmark-compare.csv"'})

    @app.post("/api/prompts")
    def api_save_prompt(body: Dict[str, Any] = Body(...)):
        try:
            pid = save_prompt_version(db, body.get("key") or body.get("name") or "", body.get("name") or "",
                                      body.get("template") or "", body.get("description") or "")
        except ValueError as exc:
            raise bad(str(exc))
        return {"id": pid, "warnings": validate_template(body.get("template") or "")}

    @app.post("/api/prompts/preview")
    def api_preview_prompt(body: Dict[str, Any] = Body(...)):
        template = body.get("template") or ""
        s = db.q1("SELECT cwe, project, category, vulnerable_code FROM samples WHERE id=?", (int(body.get("sample_id") or 4),)) \
            or db.q1("SELECT cwe, project, category, vulnerable_code FROM samples ORDER BY id LIMIT 1")
        code = (s["vulnerable_code"][:600] + "\n/* ... */") if s else "int main(void) { return 0; }"
        return {"rendered": render_prompt(template, code, s["cwe"] if s else "CWE-119"),
                "warnings": validate_template(template)}

    @app.post("/api/playground")
    async def api_playground(body: Dict[str, Any] = Body(...)):
        try:
            return await run_playground(db, manager, {k: body.get(k) for k in
                                                      ("provider", "model", "strategies", "prompt_ids", "code", "cwe", "options")})
        except ValueError as exc:
            raise bad(str(exc))

    @app.post("/api/playground/commit")
    async def api_commit(body: Dict[str, Any] = Body(...)):
        try:
            return {"diff": await fetch_commit_diff(body.get("url") or "")}
        except ValueError as exc:
            raise bad(str(exc))

    @app.post("/api/demo")
    async def api_demo():
        ids = []
        for model in ("mock-eager", "mock-cautious", "mock-balanced"):
            rid = runs_mod.create_run(db, {
                "name": f"Demo: {model}", "provider": "mock", "model": model,
                "strategies": ["baseline", "cot", "think", "think_verify"], "limit": 60, "shuffle_seed": 7,
                "options": {"concurrency": 4}})
            await manager.start(rid)
            ids.append(rid)
        return {"ids": ids}

    @app.post("/api/dataset/import")
    def api_import():
        path = settings.dataset_path
        if path is None:
            raise bad("No dataset file found. Set BREACHMARK_DATASET or put data/vulnerabilities.csv next to the app.")
        try:
            return import_dataset(db, path)
        except (ValueError, FileNotFoundError) as exc:
            raise bad(str(exc))

    return app
