"""Prompt strategies, prompt rendering, input truncation and prompt versioning.

The four built-in strategies (baseline, chain of thought, think, think & verify) follow the
prompting styles studied in "Reasoning with LLMs for Zero-Shot Vulnerability Detection"
(Zibaeirad & Vieira, 2025). The wording here is original to BreachMark. Every template asks for a
final ``VERDICT: YES`` or ``VERDICT: NO`` line so answers can be parsed reliably.
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

from .db import Database, now_iso

ANY_CWE = "any security vulnerability"

_CODE_BLOCK = "Code:\n```\n{code}\n```"
_VERDICT_LINE = (
    "Finish with one last line in exactly this form, answering YES if {cwe} is present "
    "and NO if it is not:\nVERDICT: <YES or NO>"
)

BUILTIN_PROMPTS: List[Dict[str, str]] = [
    {
        "key": "baseline",
        "name": "Baseline",
        "description": "Direct YES/NO answer with no explanation.",
        "template": (
            "You are a security expert reviewing {language} source code.\n\n"
            "Does the code below contain {cwe}?\n\n"
            + _CODE_BLOCK
            + "\n\nAnswer with exactly one word, YES or NO. Do not explain."
        ),
    },
    {
        "key": "cot",
        "name": "Chain of thought",
        "description": "Step-by-step analysis followed by a verdict line.",
        "template": (
            "You are a security expert reviewing {language} source code for {cwe}.\n\n"
            "Analyse the code step by step before you decide:\n"
            "1. Structure: list the functions, memory operations and data flows that matter for {cwe}.\n"
            "2. Patterns: point out constructs that can lead to {cwe}, and any checks or guards that prevent it.\n"
            "3. Exploitability: say whether an attacker could reach the problem and what the impact would be.\n"
            "4. Decision: judge whether the code, exactly as written, contains {cwe}.\n\n"
            + _CODE_BLOCK
            + "\n\n"
            + _VERDICT_LINE
        ),
    },
    {
        "key": "think",
        "name": "Think",
        "description": "Explicit <thinking> and <assessment> sections.",
        "template": (
            "You are a security expert reviewing {language} source code for {cwe}.\n\n"
            "Reason inside a <thinking> block first:\n"
            "- Locate places where {cwe} could occur.\n"
            "- Consider how an attacker would try to reach each place.\n"
            "- Follow the data flow and function interactions that feed those places.\n"
            "- Rule out false positives and note how confident you are in each finding.\n\n"
            "Then write an <assessment> block with your conclusion, a short justification, "
            "and a severity (Low, Medium, High or Critical).\n\n"
            + _CODE_BLOCK
            + "\n\n"
            + _VERDICT_LINE
        ),
    },
    {
        "key": "think_verify",
        "name": "Think & verify",
        "description": "Analysis with confidence scores, then a verification pass.",
        "template": (
            "You are a security expert running a multi-phase review of {language} source code for {cwe}.\n\n"
            "Phase 1, analysis. In a <thinking> block, examine the code for {cwe}, describe the attack "
            "paths you considered and note anything you are unsure about. In a <findings> block, list each "
            "suspected instance with evidence from the code. In a <confidence> block, give each finding a "
            "score from 0 to 100%.\n\n"
            "Phase 2, verification. In a <verification> block, challenge every finding scoring 90% or higher: "
            "look for guards that make it a false positive, check that it is really exploitable and consider "
            "edge cases. If no finding scores that high, analyse the code again.\n\n"
            "Phase 3, assessment. In an <assessment> block, list the verified findings, map each one to "
            "{cwe} and give a severity (Low, Medium, High or Critical).\n\n"
            + _CODE_BLOCK
            + "\n\n"
            + _VERDICT_LINE
        ),
    },
]

_PLACEHOLDER = re.compile(r"\{(cwe|code|project|category|language)\}")


def render_prompt(template: str, code: str, cwe: Optional[str] = None, project: str = "", category: str = "",
                  language: str = "C/C++") -> str:
    """Fill placeholders in a single pass, so braces in the code are never interpreted."""
    values = {"cwe": cwe or ANY_CWE, "code": code, "project": project or "", "category": category or "",
              "language": language or "source"}
    return _PLACEHOLDER.sub(lambda m: values[m.group(1)], template)


def validate_template(template: str) -> List[str]:
    """Return a list of problems (empty if the template is fine)."""
    problems = []
    if "{code}" not in template:
        problems.append("The template must contain the {code} placeholder.")
    if "{cwe}" not in template:
        problems.append("The template has no {cwe} placeholder, so the CWE will not be mentioned.")
    if "{language}" not in template:
        problems.append("The template has no {language} placeholder, so the model will not be told the language.")
    if "verdict" not in template.lower() and "yes" not in template.lower():
        problems.append("Ask the model to end with a line like 'VERDICT: YES' or 'VERDICT: NO' so answers can be parsed.")
    return problems


def apply_input_policy(code: str, max_chars: Optional[int], policy: str = "truncate") -> Tuple[str, bool, bool]:
    """Apply the context-size policy. Returns (code, truncated, skipped)."""
    if not max_chars or len(code) <= max_chars:
        return code, False, False
    if policy == "skip":
        return code, False, True
    if policy == "none":
        return code, False, False
    head_len = int(max_chars * 0.6)
    tail_len = max_chars - head_len
    head = code[:head_len]
    tail = code[-tail_len:]
    cut = head.rfind("\n")
    if cut > head_len * 0.8:
        head = head[:cut]
    nl = tail.find("\n")
    if 0 <= nl < tail_len * 0.2:
        tail = tail[nl + 1:]
    omitted = len(code) - len(head) - len(tail)
    marker = f"\n/* ... {omitted} characters omitted by BreachMark to fit the context limit ... */\n"
    return head + marker + tail, True, False


def strategy_label(key: str, version: int) -> str:
    return key if version == 1 else f"{key}@v{version}"


def seed_prompts(db: Database) -> None:
    """Insert built-in prompts. If a built-in's text changed in code: update it in place when no result
    refers to it yet, otherwise add it as a new version so old results keep their exact prompt."""
    for p in BUILTIN_PROMPTS:
        latest = db.q1("SELECT id, version, template, builtin FROM prompts WHERE key=? ORDER BY version DESC LIMIT 1",
                       (p["key"],))
        if latest is None:
            version = 1
        elif latest["template"] != p["template"]:
            used = db.scalar("SELECT COUNT(*) FROM results WHERE prompt_id=?", (latest["id"],))
            if latest["builtin"] and not used:
                db.x("UPDATE prompts SET template=?, name=?, description=? WHERE id=?",
                     (p["template"], p["name"], p["description"], latest["id"]))
                continue
            version = latest["version"] + 1
        else:
            continue
        db.x(
            "INSERT INTO prompts(key, version, name, description, template, builtin, created_at) VALUES(?,?,?,?,?,1,?)",
            (p["key"], version, p["name"], p["description"], p["template"], now_iso()),
        )


def latest_prompt_ids(db: Database, keys: List[str]) -> List[int]:
    ids = []
    for key in keys:
        row = db.q1("SELECT id FROM prompts WHERE key=? ORDER BY version DESC LIMIT 1", (key,))
        if row is None:
            raise ValueError(f"Unknown prompt strategy: {key}")
        ids.append(row["id"])
    return ids


def save_prompt_version(db: Database, key: str, name: str, template: str, description: str = "") -> int:
    """Create a new version of an existing prompt, or a new custom prompt. Returns the prompt id."""
    key = re.sub(r"[^a-z0-9_]+", "_", key.strip().lower()).strip("_")
    if not key:
        raise ValueError("Prompt key must contain letters or digits.")
    if "{code}" not in template:
        raise ValueError("The template must contain the {code} placeholder.")
    latest = db.q1("SELECT version, builtin FROM prompts WHERE key=? ORDER BY version DESC LIMIT 1", (key,))
    version = 1 if latest is None else latest["version"] + 1
    return db.x(
        "INSERT INTO prompts(key, version, name, description, template, builtin, created_at) VALUES(?,?,?,?,?,0,?)",
        (key, version, name.strip() or key, description.strip(), template, now_iso()),
    )
