"""Command line: python -m breachmark [serve|doctor|import|run|demo]."""
from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from . import __version__, config


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn
    from .app import create_app
    settings = config.get_settings()
    app = create_app()
    host = args.host or settings.host
    port = args.port or settings.port
    print(f"BreachMark {__version__} at http://{host}:{port}  (database: {settings.db_path})")
    uvicorn.run(app, host=host, port=port, log_level="warning")
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    from .db import Database
    from .providers import make_provider
    settings = config.get_settings()
    ok = True
    print(f"BreachMark {__version__}, Python {sys.version.split()[0]}")
    print(f"Database: {settings.db_path}")
    if settings.dataset_path:
        print(f"Dataset: {settings.dataset_path} (found)")
    else:
        print("Dataset: not found. Put data/vulnerabilities.csv next to the app or set BREACHMARK_DATASET.")
        ok = False
    try:
        db = Database(settings.db_path)
        db.init()
        n = db.scalar('SELECT COUNT(*) FROM samples') or 0
        print(f"Samples in database: {n}" + (" (the dataset is imported automatically on the first serve or run)" if n == 0 and settings.dataset_path else ""))
    except Exception as exc:
        print(f"Database error: {exc}")
        ok = False

    async def check(name: str):
        provider = make_provider(name, timeout=10.0)
        try:
            return await provider.ping()
        finally:
            await provider.aclose()

    for name in (args.providers or ["ollama", "openai", "anthropic"]):
        src = config.key_source(name)
        result = asyncio.run(check(name))
        status = "ok" if result["ok"] else "FAIL"
        extra = "" if name == "ollama" else f" (API key: {src})"
        print(f"{name}: {status}{extra}. {result['message']}")
        if result["ok"] and result["models"]:
            print("   models: " + ", ".join(result["models"][:12]) + (" ..." if len(result["models"]) > 12 else ""))
    return 0 if ok else 1


def cmd_import(args: argparse.Namespace) -> int:
    from .db import Database
    from .importer import import_dataset
    from .prompts import seed_prompts
    settings = config.get_settings()
    path = Path(args.csv) if args.csv else settings.dataset_path
    if path is None:
        print("No dataset file given and none found.")
        return 1
    db = Database(settings.db_path)
    db.init()
    seed_prompts(db)
    result = import_dataset(db, path, replace=args.replace)
    print(f"Imported {result['rows']} rows ({result['inserted']} new, {result['updated']} updated, "
          f"{result['skipped']} skipped). {result['total']} samples in the database.")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    """Headless run, for servers without a browser."""
    from .db import Database
    from .importer import ensure_dataset
    from .prompts import seed_prompts
    from .runner import RunManager
    from .runs import create_run, run_progress
    from .analytics import metrics_by_strategy
    settings = config.get_settings()
    db = Database(settings.db_path)
    db.init()
    seed_prompts(db)
    ensure_dataset(db, settings.dataset_path)
    spec = {"name": args.name, "provider": args.provider, "model": args.model, "strategies": args.strategies,
            "limit": args.limit, "shuffle_seed": args.seed,
            "filters": {"cwe": args.cwe or "", "project": args.project or "", "max_noise": args.max_noise or ""},
            "options": {"concurrency": args.concurrency, "base_url": args.base_url, "judge": args.judge, "blind": args.blind,
                        "max_input_chars": args.max_input_chars}}
    try:
        run_id = create_run(db, spec)
    except ValueError as exc:
        print(f"Cannot create run: {exc}")
        return 1
    print(f"Run {run_id} created. Open the Runs page to follow it, or watch this terminal.")

    async def go():
        manager = RunManager(db)
        await manager.start(run_id)
        try:
            while manager.is_active(run_id):
                p = run_progress(db, run_id)
                print(f"\r{p['finished']}/{p['total']} ({p['percent']}%)  failed: {p['counts']['error']}   ", end="", flush=True)
                await asyncio.sleep(2)
        except KeyboardInterrupt:
            manager.pause(run_id)
            await manager.wait(run_id)
            print("\nPaused. Resume it from the Runs page or by starting the same run again.")
            return
        await manager.wait(run_id)
        p = run_progress(db, run_id)
        print(f"\rFinished: {p['status']}. {p['finished']}/{p['total']} answers, {p['counts']['error']} failed.")
        if p["error"]:
            print(p["error"])
        for strategy, m in metrics_by_strategy(db, run_id).items():
            acc = "n/a" if m["accuracy"] is None else f"{m['accuracy'] * 100:.1f}%"
            print(f"  {strategy:14s} n={m['n']:4d}  accuracy {acc}")

    asyncio.run(go())
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="breachmark", description="Benchmark LLMs on real vulnerability detection.")
    sub = parser.add_subparsers(dest="cmd")
    s = sub.add_parser("serve", help="start the web app (default)")
    s.add_argument("--host")
    s.add_argument("--port", type=int)
    d = sub.add_parser("doctor", help="check the dataset, database and model servers")
    d.add_argument("providers", nargs="*", choices=["ollama", "openai", "anthropic"], help="which providers to test")
    i = sub.add_parser("import", help="import a dataset CSV")
    i.add_argument("csv", nargs="?")
    i.add_argument("--replace", action="store_true", help="delete existing samples first")
    r = sub.add_parser("run", help="run a benchmark without the web UI")
    r.add_argument("--provider", default="ollama", choices=["ollama", "openai", "anthropic", "mock"])
    r.add_argument("--model", required=True)
    r.add_argument("--strategies", nargs="+", default=["baseline", "cot", "think", "think_verify"])
    r.add_argument("--limit", type=int)
    r.add_argument("--seed", type=int, default=1)
    r.add_argument("--cwe")
    r.add_argument("--project")
    r.add_argument("--max-noise", dest="max_noise")
    r.add_argument("--concurrency", type=int)
    r.add_argument("--base-url", dest="base_url")
    r.add_argument("--max-input-chars", dest="max_input_chars", type=int)
    r.add_argument("--judge", action="store_true")
    r.add_argument("--blind", action="store_true", help="do not tell the model which CWE to look for")
    r.add_argument("--name")
    args = parser.parse_args(argv)
    if args.cmd in (None, "serve"):
        if args.cmd is None:
            args.host = args.port = None
        return cmd_serve(args)
    return {"doctor": cmd_doctor, "import": cmd_import, "run": cmd_run}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
