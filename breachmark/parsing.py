"""Turn raw model output into a verdict: 1 = vulnerable (YES), 0 = not vulnerable (NO), 2 = ambiguous."""
from __future__ import annotations

import re
from typing import Tuple

YES, NO, AMBIGUOUS = 1, 0, 2

_THINK_BLOCK = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)
_THINK_OPEN = re.compile(r"<think>.*", re.DOTALL | re.IGNORECASE)

# Do not accept "VERDICT: YES or NO" (the model echoing the instruction).
_NOT_ECHO = r"(?!\s*(?:/|\bor\b)\s*(?:yes|no)\b)"
_LEAD = r"\s*[:\-=]?\s*[\*_`\"'\[\(<]*\s*"

_VERDICT = re.compile(r"verdict" + _LEAD + r"(yes|no)\b" + _NOT_ECHO, re.IGNORECASE)
_FINAL = re.compile(
    r"final\s+(?:decision|answer|verdict|assessment|conclusion)" + _LEAD + r"(yes|no)\b" + _NOT_ECHO,
    re.IGNORECASE,
)
_LABELLED = re.compile(
    r"(?:vulnerab\w*|cwe-\d+)\s+(?:is\s+)?(?:present|found|detected|confirmed)\s*[:\-=]\s*[\*_`]*\s*(yes|no)\b",
    re.IGNORECASE,
)
_BARE = re.compile(r"^[\W_]*(yes|no)\b", re.IGNORECASE)


def strip_thinking(text: str) -> str:
    """Remove <think>...</think> reasoning traces (e.g. from DeepSeek-R1), including unterminated ones."""
    text = _THINK_BLOCK.sub("", text or "")
    return _THINK_OPEN.sub("", text).strip()


def _last(pattern: "re.Pattern[str]", text: str):
    matches = list(pattern.finditer(text))
    return matches[-1] if matches else None


def parse_verdict(text: str, allow_bare: bool = False) -> Tuple[int, str]:
    """Return (verdict, method). Method is one of verdict, final, label, bare, none."""
    body = strip_thinking(text)
    if not body:
        return AMBIGUOUS, "none"
    for method, pattern in (("verdict", _VERDICT), ("final", _FINAL), ("label", _LABELLED)):
        match = _last(pattern, body)
        if match:
            return (YES if match.group(1).lower() == "yes" else NO), method
    if allow_bare and len(body) <= 200:
        match = _BARE.match(body)
        if match:
            return (YES if match.group(1).lower() == "yes" else NO), "bare"
    return AMBIGUOUS, "none"


JUDGE_PROMPT = (
    "Below is a security analysis of a piece of code. Decide what its final conclusion is.\n"
    "Reply with exactly one word: YES if it concludes the vulnerability is present, NO if it concludes "
    "it is not present, or UNCLEAR if it does not commit to either.\n\nAnalysis:\n{analysis}\n"
)


def parse_judge(text: str) -> int:
    body = strip_thinking(text).upper()
    match = re.search(r"\b(YES|NO|UNCLEAR)\b", body)
    if not match:
        return AMBIGUOUS
    return {"YES": YES, "NO": NO}.get(match.group(1), AMBIGUOUS)
