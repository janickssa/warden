"""Structured diff between a failed plan and its revision (invariant 5, README 17.3)."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

from warden.plans.models import Step


@dataclass(frozen=True, slots=True)
class DiffRow:
    old_n: int | None
    new_n: int | None
    op: Literal["same", "added", "removed"]
    old_command: str | None
    new_command: str | None


def _key(s: Step) -> tuple[str, str, str]:
    return (s.kind.value, s.command, s.cwd)


def diff_steps(old: Sequence[Step], new: Sequence[Step]) -> list[DiffRow]:
    """LCS over (kind, command, cwd). A changed step shows as removed + added."""
    a, b = [_key(s) for s in old], [_key(s) for s in new]
    lcs = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) - 1, -1, -1):
        for j in range(len(b) - 1, -1, -1):
            lcs[i][j] = lcs[i + 1][j + 1] + 1 if a[i] == b[j] else max(lcs[i + 1][j], lcs[i][j + 1])
    rows: list[DiffRow] = []
    i = j = 0
    while i < len(a) and j < len(b):
        if a[i] == b[j]:
            rows.append(DiffRow(old[i].n, new[j].n, "same", old[i].command, new[j].command))
            i += 1
            j += 1
        elif lcs[i + 1][j] >= lcs[i][j + 1]:
            rows.append(DiffRow(old[i].n, None, "removed", old[i].command, None))
            i += 1
        else:
            rows.append(DiffRow(None, new[j].n, "added", None, new[j].command))
            j += 1
    rows += [DiffRow(s.n, None, "removed", s.command, None) for s in old[i:]]
    rows += [DiffRow(None, s.n, "added", None, s.command) for s in new[j:]]
    return rows


def changed_steps(rows: Sequence[DiffRow]) -> int:
    return sum(1 for r in rows if r.op != "same")
