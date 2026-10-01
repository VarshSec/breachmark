"""Runtime configuration: environment variables, an optional .env file, and in-memory API keys."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional

PACKAGE_DIR = Path(__file__).resolve().parent
ROOT_DIR = PACKAGE_DIR.parent


def load_dotenv(path: Path) -> None:
    """Minimal .env loader. Existing environment variables always win."""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


load_dotenv(Path.cwd() / ".env")

# Environment variable names that may hold an API key, per provider.
KEY_ENV_VARS = {
    "openai": ("BREACHMARK_API_KEY", "OPENAI_API_KEY"),
    "anthropic": ("ANTHROPIC_API_KEY",),
}

# Keys typed into the UI live only in this process and are never written to disk.
_session_keys: Dict[str, str] = {}


def set_session_key(provider: str, key: str) -> None:
    if key and key.strip():
        _session_keys[provider] = key.strip()
    else:
        _session_keys.pop(provider, None)


def get_api_key(provider: str) -> Optional[str]:
    if provider in _session_keys:
        return _session_keys[provider]
    for var in KEY_ENV_VARS.get(provider, ()):
        value = os.environ.get(var)
        if value:
            return value.strip()
    return None


def key_source(provider: str) -> str:
    """Where the key comes from: 'session', 'environment', or 'missing'."""
    if provider in _session_keys:
        return "session"
    for var in KEY_ENV_VARS.get(provider, ()):
        if os.environ.get(var):
            return "environment"
    return "missing"


@dataclass
class Settings:
    db_path: Path
    dataset_path: Optional[Path]
    ollama_host: str
    openai_base_url: str
    anthropic_base_url: str
    host: str
    port: int


def _find_dataset() -> Optional[Path]:
    explicit = os.environ.get("BREACHMARK_DATASET")
    if explicit:
        return Path(explicit).expanduser().resolve()
    for candidate in (Path.cwd() / "data" / "vulnerabilities.csv", ROOT_DIR / "data" / "vulnerabilities.csv"):
        if candidate.is_file():
            return candidate
    return None


def get_settings() -> Settings:
    """Read settings from the environment on each call so tests and the CLI can override them."""
    return Settings(
        db_path=Path(os.environ.get("BREACHMARK_DB", "breachmark.db")).expanduser().resolve(),
        dataset_path=_find_dataset(),
        ollama_host=os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/"),
        openai_base_url=os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/"),
        anthropic_base_url=os.environ.get("ANTHROPIC_BASE_URL", "https://api.anthropic.com").rstrip("/"),
        host=os.environ.get("BREACHMARK_HOST", "127.0.0.1"),
        port=int(os.environ.get("BREACHMARK_PORT", "8000")),
    )
