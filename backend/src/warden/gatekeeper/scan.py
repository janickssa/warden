"""`injection-scan`: a deterministic reviewer for untrusted text (PLAN M5).

It runs on everything the models would read as untrusted (goal, purposes, diagnosis notes, output) and looks
for signs that someone is trying to steer the review. It can only escalate (never allow or deny), so a false
positive costs a closer human look and nothing else. Unlike a model, it can't be talked out of it.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Sequence

from warden.plans.models import GatekeeperVerdict, Risk, StepVerdictNote, Verdict

NAME = "injection-scan"
MODEL = "rules"

_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "instruction override",
        re.compile(
            r"\b(ignore|disregard|forget|override)\b.{0,40}\b(previous|prior|above|earlier|all|system|your)\b.{0,30}\b(instruction|instructions|prompt|rules|guidelines|directions)",
            re.I | re.S,
        ),
    ),
    (
        "new instructions",
        re.compile(r"\b(new|updated|real|actual)\s+(instructions|rules|task|system prompt)\s*[:\-]", re.I),
    ),
    (
        "role play",
        re.compile(
            r"\byou are now\b|\bact as (an?|the)\b|\bpretend (to be|you are)\b|\bdeveloper mode\b|\bjailbreak",  # noqa: E501
            re.I,
        ),
    ),
    (
        "claimed approval",
        re.compile(
            r"\b(already|pre-?)\s*(been\s+)?(approved|authori[sz]ed|signed off|cleared)\b|\b(user|owner|admin|human)\s+(has\s+)?(approved|authori[sz]ed|confirmed|allowed)\b",  # noqa: E501
            re.I,
        ),
    ),
    (
        "reviewer address",
        re.compile(
            r"\b(gatekeeper|reviewer|security review(er)?|safety check|ai model|language model|llm)\b.{0,60}\b(must|should|will|need to|has to)\b.{0,40}\b(allow|approve|pass|accept|ignore)",  # noqa: E501
            re.I | re.S,
        ),
    ),
    ("verdict injection", re.compile(r"[\"']?verdict[\"']?\s*[:=]\s*[\"']?(allow|approve|safe)", re.I)),
    (
        "delimiter",
        re.compile(
            r"</?\s*(untrusted|system|assistant|instructions?|im_start|im_end)\b|\[/?INST\]|<\|[a-z_]+\|>",
            re.I,
        ),
    ),
    ("hidden escape", re.compile(r"\x1b\[|\x1b\]")),
)


def _invisible(text: str) -> bool:
    return any(
        unicodedata.category(ch) in ("Cf", "Co", "Cn")
        or (unicodedata.category(ch) == "Cc" and ch not in "\n\t\r")
        for ch in text
    )


def findings(texts: Sequence[str]) -> list[str]:
    hits: list[str] = []
    for text in texts:
        for label, pat in _PATTERNS:
            if label not in hits and pat.search(text):
                hits.append(label)
        if "invisible characters" not in hits and _invisible(text):
            hits.append("invisible characters")
    return hits


def scan(texts: Sequence[str], steps: Sequence[int]) -> GatekeeperVerdict:
    hits = findings(texts)
    if not hits:
        return GatekeeperVerdict(
            name=NAME,
            model=MODEL,
            verdict=Verdict.ALLOW,
            risk=Risk.LOW,
            summary="No injection markers in the untrusted text",
            per_step=tuple(StepVerdictNote(n=n, matches_goal=True) for n in steps),
        )
    return GatekeeperVerdict(
        name=NAME,
        model=MODEL,
        verdict=Verdict.ESCALATE,
        risk=Risk.MEDIUM,
        summary=f"Untrusted text tries to steer the review ({', '.join(hits)}) · escalate",
        per_step=tuple(StepVerdictNote(n=n, matches_goal=True) for n in steps),
    )
