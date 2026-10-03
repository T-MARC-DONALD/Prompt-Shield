"""Defense engine — combine detection layers, score, and decide an action.

Runs the syntax, semantic, and encoding layers over a piece of text, combines
their detections into a single risk score, and maps that score to an action
(allow / alert / sanitize / block) according to the requested mode.
"""

import re
from dataclasses import dataclass, field

from defenses.types import Detection, DefenseAction
from defenses.syntax import syntax_scan
from defenses.semantic import semantic_scan
from defenses.encoding import encoding_scan

# Zero-tolerance default: a single confident detection is enough to act.
DEFAULT_THRESHOLD = 0.6

# Structural spans removed during sanitization (pattern, replacement).
_SANITIZE_PATTERNS = [
    re.compile(r"\[/?INST\b[^\]]*\]", re.IGNORECASE),          # [INST: ...]
    re.compile(r"<!--.*?-->", re.IGNORECASE | re.DOTALL),      # HTML comments
    re.compile(r"\{\{.*?\}\}|\{%.*?%\}", re.DOTALL),           # template blocks
    re.compile(r"<div[^>]*(?:display\s*:\s*none|visibility\s*:\s*hidden)[^>]*>.*?</div>",
               re.IGNORECASE | re.DOTALL),                     # hidden CSS containers
]


@dataclass
class DefenseResult:
    """Outcome of analysing a piece of text for prompt injection."""
    action: DefenseAction
    score: float
    detections: list[Detection] = field(default_factory=list)
    sanitized: str = ""
    explanation: str = ""


def sanitize(text: str) -> str:
    """Strip structural injection markers, preserving legitimate content."""
    cleaned = text
    for pattern in _SANITIZE_PATTERNS:
        cleaned = pattern.sub("", cleaned)
    # Collapse whitespace left behind by removed spans.
    cleaned = re.sub(r"[ \t]{2,}", " ", cleaned)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    return cleaned.strip()


def _scan(text: str) -> list[Detection]:
    return syntax_scan(text) + semantic_scan(text) + encoding_scan(text)


def analyze(text: str, tier: int | None = None, mode: str = "block",
            threshold: float = DEFAULT_THRESHOLD) -> DefenseResult:
    """Analyse `text` for prompt injection and decide what to do.

    mode: "block" | "sanitize" | "alert" — how to respond when the risk score
    meets `threshold`. Clean text is always ALLOWed regardless of mode.
    """
    detections = _scan(text or "")
    score = max((d.score for d in detections), default=0.0)

    if score < threshold:
        return DefenseResult(DefenseAction.ALLOW, score, detections, text or "",
                             "No injection indicators above threshold.")

    reasons = "; ".join(dict.fromkeys(d.reason for d in detections))
    explanation = f"Injection risk {score:.0%} — {reasons}"

    if mode == "sanitize":
        return DefenseResult(DefenseAction.SANITIZE, score, detections,
                             sanitize(text), explanation)
    if mode == "alert":
        return DefenseResult(DefenseAction.ALERT, score, detections, text,
                             explanation)
    return DefenseResult(DefenseAction.BLOCK, score, detections, "", explanation)
