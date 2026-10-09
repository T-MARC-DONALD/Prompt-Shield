"""Defense engine -- combine detection layers, score, and decide an action.

Core scan (unchanged): syntax + semantic + encoding layers -> score -> action.

The upgraded stack adds four input stages and one output stage around it:

    sanitizer  -> marker-level neutralization of embedded instructions
    hierarchy  -> instruction/data separation + policy fences
    anomaly    -> extraction probing / long-context abuse / flood patterns
    limits     -> rate + size + volume controls per session
    output_guard -> leak / secret / PII / canary screening of responses

Use `analyze()` for the classic single-text decision (kept stable for the
evaluation pipeline), and `screen_input()` / `screen_output()` for the full
guarded stack.
"""

import re
from dataclasses import dataclass, field

from defenses.types import Detection, DefenseAction
from defenses.syntax import syntax_scan
from defenses.semantic import semantic_scan
from defenses.encoding import encoding_scan
from defenses.sanitizer import screen as sanitizer_screen
from defenses.hierarchy import enforce as hierarchy_enforce
from defenses.output_guard import scan as output_scan, OutputReport
from defenses.limits import SessionGuard, RateLimiter

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

# Risk contribution of each sanitizer action kind (full-pipeline mode).
_SANITIZER_SCORES = {
    "hidden_instruction": 0.90,
    "inst_block": 0.85,
    "directive_key": 0.85,
    "comment_instruction": 0.80,
    "zero_width": 0.50,
    "bidi_control": 0.50,
    "hidden_html": 0.50,
    "unicode_normalized": 0.30,
}


@dataclass
class DefenseResult:
    """Outcome of analysing a piece of text for prompt injection."""
    action: DefenseAction
    score: float
    detections: list[Detection] = field(default_factory=list)
    sanitized: str = ""
    explanation: str = ""


@dataclass
class PipelineResult:
    """Outcome of the full guarded pipeline (screen_input)."""
    action: str                     # "allow" | "alert" | "sanitize" | "block"
    score: float
    reasons: list = field(default_factory=list)
    detections: list = field(default_factory=list)     # list[Detection]
    cleaned_text: str = ""          # neutralized input (no fences)
    guarded_text: str = ""          # fenced input for the consuming model
    sanitization: dict = field(default_factory=dict)
    hierarchy: dict = field(default_factory=dict)
    limits: dict = field(default_factory=dict)
    anomaly: dict = field(default_factory=dict)
    explanation: str = ""

    def as_dict(self) -> dict:
        return {
            "action": self.action,
            "score": self.score,
            "reasons": self.reasons,
            "detections": [{"layer": d.layer, "marker": d.marker,
                            "reason": d.reason, "score": d.score}
                           for d in self.detections],
            "cleaned_text": self.cleaned_text,
            "guarded_text": self.guarded_text,
            "sanitization": self.sanitization,
            "hierarchy": self.hierarchy,
            "limits": self.limits,
            "anomaly": self.anomaly,
            "explanation": self.explanation,
        }


def sanitize(text: str) -> str:
    """Strip structural injection markers, preserving legitimate content."""
    cleaned = text
    for pattern in _SANITIZE_PATTERNS:
        cleaned = pattern.sub("", cleaned)
    # Collapse whitespace left behind by removed spans.
    cleaned = re.sub(r"[ \t]{2,}", " ", cleaned)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    # Upgraded pass: zero-width / bidi / hidden-HTML / directive keys.
    try:
        cleaned = sanitizer_screen(cleaned)["cleaned"]
    except Exception:
        pass
    return cleaned.strip()


def _scan(text: str) -> list[Detection]:
    return syntax_scan(text) + semantic_scan(text) + encoding_scan(text)


def analyze(text: str, tier: int | None = None, mode: str = "block",
            threshold: float = DEFAULT_THRESHOLD) -> DefenseResult:
    """Analyse `text` for prompt injection and decide what to do.

    mode: "block" | "sanitize" | "alert" -- how to respond when the risk score
    meets `threshold`. Clean text is always ALLOWed regardless of mode.
    """
    detections = _scan(text or "")
    score = max((d.score for d in detections), default=0.0)

    if score < threshold:
        return DefenseResult(DefenseAction.ALLOW, score, detections, text or "",
                             "No injection indicators above threshold.")

    reasons = "; ".join(dict.fromkeys(d.reason for d in detections))
    explanation = f"Injection risk {score:.0%} -- {reasons}"

    if mode == "sanitize":
        return DefenseResult(DefenseAction.SANITIZE, score, detections,
                             sanitize(text), explanation)
    if mode == "alert":
        return DefenseResult(DefenseAction.ALERT, score, detections, text,
                             explanation)
    return DefenseResult(DefenseAction.BLOCK, score, detections, "", explanation)


# --------------------------------------------------------------------------
# Full guarded pipeline
# --------------------------------------------------------------------------

_DEFAULT_GUARD: SessionGuard | None = None


def _default_guard() -> SessionGuard:
    """Process-wide SessionGuard used when the caller does not pass one."""
    global _DEFAULT_GUARD
    if _DEFAULT_GUARD is None:
        _DEFAULT_GUARD = SessionGuard()
    return _DEFAULT_GUARD


def screen_input(text: str, tier: int | None = None, mode: str = "block",
                 session: SessionGuard | None = None, session_id: str = "anon",
                 policy: dict | None = None,
                 threshold: float = DEFAULT_THRESHOLD) -> PipelineResult:
    """Run the full input-side stack: limits, anomaly, scan, screen, hierarchy.

    mode controls what happens when the risk score meets `threshold`
    ("block" | "sanitize" | "alert"). Limits violations always block.
    """
    guard = session or _default_guard()
    usage = guard.screen(text or "", session_id=session_id)
    limits = usage["limits"]
    anomaly = usage["anomaly"]

    detections = _scan(text or "")
    hier = hierarchy_enforce(text or "", policy)
    san = hier["sanitization"]
    score = max((d.score for d in detections), default=0.0)
    reasons = [d.reason for d in detections]

    for a in san["actions"]:
        score = max(score, _SANITIZER_SCORES.get(a["kind"], 0.4))
        reasons.append(a["detail"])

    if hier["conflicts"]:
        score = max(score, 0.80)
        reasons.append(f"{hier['conflicts']} instruction-like span(s) inside data content")

    if anomaly["score"] >= 0.45:
        score = max(score, anomaly["score"])
        reasons.extend(anomaly["flags"])

    if not limits["allowed"]:
        score = max(score, 0.95)
        reasons.insert(0, f"rate/usage controls: {limits['reason']}")

    score = round(min(score, 0.99), 2)
    reasons = list(dict.fromkeys(reasons))

    if not limits["allowed"]:
        action = "block"
    elif score >= threshold:
        action = mode if mode in ("block", "sanitize", "alert") else "block"
    else:
        action = "allow"

    explanation = ("No risks above threshold." if action == "allow"
                   else f"Risk {score:.0%} -- " + "; ".join(reasons[:4]))

    return PipelineResult(
        action=action, score=score, reasons=reasons, detections=detections,
        cleaned_text=hier["cleaned"], guarded_text=hier["guarded"],
        sanitization=san,
        hierarchy={"segments": hier["segments"], "conflicts": hier["conflicts"]},
        limits=limits, anomaly=anomaly, explanation=explanation,
    )


def screen_output(text: str, mode: str = "redact", canaries: list | None = None,
                  unsafe_terms: list | None = None) -> OutputReport:
    """Screen a model response for leaks / secrets / PII / canaries.

    mode: "redact" (default) | "flag" | "block".
    """
    return output_scan(text or "", mode=mode, canaries=canaries,
                       unsafe_terms=unsafe_terms)
