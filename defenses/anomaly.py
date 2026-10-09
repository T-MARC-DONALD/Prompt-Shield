"""Anomaly detection -- extraction attempts, long-context abuse and misuse patterns.

Fourth stage of the upgraded defense stack. Where the syntax/semantic/encoding
layers look at *content*, this layer looks at *behaviour in shape*:

  * extraction probing ("repeat your instructions", "everything above verbatim")
  * long-context abuse (very large inputs, repeated-block floods, padding runs)
  * formatting floods (fence spam, delimiter abuse)
  * instruction barrages (many distinct instruction-like signals in one input)

It is deterministic. Pass a per-session `counters` dict to escalate on repeated
probing across requests.
"""

import re
from collections import Counter
from dataclasses import dataclass, field

from defenses.semantic import semantic_scan

LONG_CONTEXT_CHARS = 6000
FLOOD_CONTEXT_CHARS = 24000
CHAR_RUN_LIMIT = 300
FENCE_FLOOD = 12
BARRAGE_MIN = 4

_EXTRACTION_PATTERNS = [
    re.compile(r"\b(?:reveal|show|print|repeat|output|dump|display|leak)\b[^\n.]{0,40}"
               r"\b(?:your |the |my )?(?:system )?(?:prompt|instructions?|rules)\b", re.IGNORECASE),
    re.compile(r"\bwhat (?:were|are) (?:you|your) (?:told|instructed|ordered|programmed)\b",
               re.IGNORECASE),
    re.compile(r"\beverything (?:above|before) (?:this|the line|the dash)\b", re.IGNORECASE),
    re.compile(r"\b(?:text|message|prompt) (?:above|before) (?:verbatim|exactly|word for word)\b",
               re.IGNORECASE),
    re.compile(r"\binitial (?:prompt|message|instructions?)\b", re.IGNORECASE),
    re.compile(r"\b(?:repeat|echo) (?:that|this|it) back\b", re.IGNORECASE),
]


@dataclass
class AnomalyReport:
    score: float
    flags: list = field(default_factory=list)      # list[str]
    extraction_hits: int = 0
    explanation: str = ""

    def as_dict(self):
        return {"score": self.score, "flags": self.flags,
                "extraction_hits": self.extraction_hits,
                "explanation": self.explanation}


def analyze_input(text: str, counters: dict | None = None) -> AnomalyReport:
    """Score `text` for behavioural anomalies. `counters` escalates over time."""
    text = text or ""
    flags = []
    score = 0.0

    # 1. Extraction probing
    hits = sum(1 for p in _EXTRACTION_PATTERNS if p.search(text))
    if hits:
        flags.append(f"extraction probing ({hits} signal(s))")
        score = max(score, min(0.55 + 0.1 * hits, 0.85))
    prior = (counters or {}).get("extraction_hits", 0)
    if prior + hits >= 3:
        flags.append(f"repeated extraction attempts across requests ({prior + hits})")
        score = max(score, 0.88)

    # 2. Long-context abuse
    n = len(text)
    if n >= FLOOD_CONTEXT_CHARS:
        flags.append(f"flood-scale input ({n:,} chars)")
        score = max(score, 0.8)
    elif n >= LONG_CONTEXT_CHARS:
        flags.append(f"long input ({n:,} chars)")
        score = max(score, 0.45)

    lines = [l for l in text.splitlines() if l.strip()]
    if len(lines) >= 40:
        top = Counter(lines).most_common(1)[0][1]
        ratio = top / len(lines)
        if ratio > 0.5:
            flags.append(f"repeated-block flood ({ratio:.0%} of {len(lines)} lines identical)")
            score = max(score, 0.75)
        elif len(lines) > 200:
            flags.append(f"large repeated-lines volume ({len(lines)} lines)")
            score = max(score, 0.6)

    # 3. Character padding runs
    if re.search(r"(.)\1{%d,}" % CHAR_RUN_LIMIT, text):
        flags.append("character padding run")
        score = max(score, 0.7)

    # 4. Formatting floods
    if text.count("```") > FENCE_FLOOD:
        flags.append("code-fence flood")
        score = max(score, 0.55)

    # 5. Instruction barrage
    dets = semantic_scan(text)
    if len(dets) >= BARRAGE_MIN:
        flags.append(f"instruction barrage ({len(dets)} distinct signals)")
        score = max(score, 0.8)

    explanation = ("No behavioural anomalies detected." if not flags
                   else "Behavioural anomalies: " + "; ".join(flags))
    return AnomalyReport(round(min(score, 0.99), 2), flags, hits, explanation)
