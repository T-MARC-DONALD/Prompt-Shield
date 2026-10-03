"""PromptShield defense layer — layered heuristic defense against prompt injection.

Public API:
    from defenses import analyze, DefenseAction, DefenseResult

    result = analyze(text, mode="block")   # "block" | "sanitize" | "alert"
    if result.action is DefenseAction.BLOCK:
        ...
"""

from defenses.types import Detection, DefenseAction
from defenses.engine import analyze, sanitize, DefenseResult, DEFAULT_THRESHOLD

__all__ = [
    "analyze", "sanitize", "DefenseResult", "DefenseAction",
    "Detection", "DEFAULT_THRESHOLD",
]
