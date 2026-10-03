"""Syntax detection layer — structural injection markers.

Detects the *shape* of an injection (tags, comments, hidden containers)
without needing to understand the instruction semantically.
"""

import re
from defenses.types import Detection

# (compiled pattern, marker label, reason, score)
_SYNTAX_PATTERNS = [
    (re.compile(r"\[/?INST\b", re.IGNORECASE), "INST tag",
     "instruction tag [INST] embedded in content", 0.9),
    (re.compile(r"<!--.*?-->", re.IGNORECASE | re.DOTALL), "HTML comment",
     "HTML comment can hide instructions from a human reader", 0.7),
    (re.compile(r"\{\{.*?\}\}|\{%.*?%\}", re.DOTALL), "template syntax",
     "template placeholder syntax ({{ }} / {% %}) embedded in content", 0.75),
    (re.compile(r"display\s*:\s*none|visibility\s*:\s*hidden", re.IGNORECASE),
     "hidden CSS container",
     "content hidden from the human reader via CSS", 0.85),
]


def syntax_scan(text: str) -> list[Detection]:
    """Return structural-marker detections found in `text`."""
    if not text:
        return []
    detections = []
    for pattern, marker, reason, score in _SYNTAX_PATTERNS:
        if pattern.search(text):
            detections.append(Detection("syntax", marker, reason, score))
    return detections
