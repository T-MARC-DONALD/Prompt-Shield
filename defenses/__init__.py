"""PromptShield defense layer -- layered heuristic defense against prompt injection.

Core API (stable):

    from defenses import analyze, DefenseAction, DefenseResult

    result = analyze(text, mode="block")   # "block" | "sanitize" | "alert"
    if result.action is DefenseAction.BLOCK:
        ...

Upgraded full stack:

    from defenses import screen_input, screen_output, SessionGuard

    guard = SessionGuard()                       # keep one per process
    r = screen_input(text, session_id="user-1", session=guard, mode="block")
    # r.action, r.score, r.reasons, r.cleaned_text, r.guarded_text, ...

    out = screen_output(model_reply, mode="redact", canaries=["CANARY-..."])
    # out.action, out.findings, out.cleaned
"""

from defenses.types import Detection, DefenseAction
from defenses.engine import (
    analyze, sanitize, DefenseResult, PipelineResult,
    screen_input, screen_output, DEFAULT_THRESHOLD,
)
from defenses.limits import SessionGuard, RateLimiter, LimitDecision
from defenses.sanitizer import screen as sanitize_and_screen
from defenses.hierarchy import enforce as enforce_hierarchy, DEFAULT_POLICY
from defenses.output_guard import scan as scan_output, OutputReport, OutputFinding
from defenses.anomaly import analyze_input

__all__ = [
    # core
    "analyze", "sanitize", "DefenseResult", "DefenseAction",
    "Detection", "DEFAULT_THRESHOLD",
    # upgraded stack
    "screen_input", "screen_output", "PipelineResult",
    "SessionGuard", "RateLimiter", "LimitDecision",
    "sanitize_and_screen", "enforce_hierarchy", "DEFAULT_POLICY",
    "scan_output", "OutputReport", "OutputFinding",
    "analyze_input",
]
