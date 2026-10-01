"""Line-level diff between vulnerable and patched code, shaped for rendering."""
from __future__ import annotations

import difflib
from typing import Any, Dict, List


def diff_rows(old: str, new: str, context: int = 3, full: bool = False, max_rows: int = 6000) -> Dict[str, Any]:
    a, b = old.split("\n"), new.split("\n")
    # Trim identical head and tail first: the two versions of a patched function are nearly identical.
    head = 0
    while head < len(a) and head < len(b) and a[head] == b[head]:
        head += 1
    tail = 0
    while tail < len(a) - head and tail < len(b) - head and a[len(a) - 1 - tail] == b[len(b) - 1 - tail]:
        tail += 1
    mid_a, mid_b = a[head:len(a) - tail], b[head:len(b) - tail]
    ops = difflib.SequenceMatcher(None, mid_a, mid_b).get_opcodes()

    rows: List[Dict[str, Any]] = []
    for i in range(head):
        rows.append({"kind": "ctx", "old": i + 1, "new": i + 1, "text": a[i]})
    for tag, i1, i2, j1, j2 in ops:
        if tag == "equal":
            for k in range(i2 - i1):
                rows.append({"kind": "ctx", "old": head + i1 + k + 1, "new": head + j1 + k + 1, "text": mid_a[i1 + k]})
            continue
        for k in range(i1, i2):
            rows.append({"kind": "del", "old": head + k + 1, "new": None, "text": mid_a[k]})
        for k in range(j1, j2):
            rows.append({"kind": "add", "old": None, "new": head + k + 1, "text": mid_b[k]})
    for t in range(tail):
        rows.append({"kind": "ctx", "old": len(a) - tail + t + 1, "new": len(b) - tail + t + 1, "text": a[len(a) - tail + t]})

    added = sum(r["kind"] == "add" for r in rows)
    removed = sum(r["kind"] == "del" for r in rows)
    if not full:
        keep = [False] * len(rows)
        for idx, r in enumerate(rows):
            if r["kind"] != "ctx":
                for j in range(max(0, idx - context), min(len(rows), idx + context + 1)):
                    keep[j] = True
        shown: List[Dict[str, Any]] = []
        skipped = 0
        for idx, r in enumerate(rows):
            if keep[idx]:
                if skipped:
                    shown.append({"kind": "gap", "old": None, "new": None, "text": f"{skipped} unchanged lines"})
                    skipped = 0
                shown.append(r)
            else:
                skipped += 1
        if skipped:
            shown.append({"kind": "gap", "old": None, "new": None, "text": f"{skipped} unchanged lines"})
        rows = shown
    truncated = len(rows) > max_rows
    return {"rows": rows[:max_rows], "added": added, "removed": removed, "truncated": truncated,
            "total_rows": len(rows), "identical": added == 0 and removed == 0}
