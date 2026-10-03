"""Semantic detection layer — instruction-like intent.

Detects wording that tries to redirect the model's behaviour: override
verbs aimed at instructions/rules, requests to expose the system prompt,
authority/urgency framing, and injected directive keys in structured data.
"""

import re
from defenses.types import Detection

# Persona / jailbreak tokens matched case-sensitively to avoid flagging the
# common name "Dan"; the all-caps jailbreak personas are the real signal.
_CASE_SENSITIVE = [
    (re.compile(r"\bDAN\b"), "DAN persona", "DAN jailbreak persona", 0.85),
    (re.compile(r"\bJAILBREAK\b"), "JAILBREAK persona",
     "JAILBREAK alter-ego persona", 0.85),
    (re.compile(r"\bUNRESTRICTED MODE\b"), "unrestricted mode",
     "request to enter an 'unrestricted mode'", 0.85),
]

# (compiled pattern, marker label, reason, score)
_SEMANTIC_PATTERNS = [
    # Override verbs aimed at instructions / rules / guidelines
    (re.compile(r"\b(ignore|disregard|forget|override|bypass)\w*.{0,40}"
                r"\b(instruction|rule|guideline|prompt|constraint|filter|"
                r"restriction|fine.?tuning|safety\s+training)s?\b",
                re.IGNORECASE | re.DOTALL),
     "instruction override",
     "language attempting to override prior instructions/rules", 0.85),

    # References to the system prompt / hidden instructions / model internals
    (re.compile(r"\b(system\s*prompt|system\s*message|system\s*instruction|"
                r"context\s*window|your\s*(original\s+|initial\s+)?instructions|"
                r"prior\s+instructions|previous\s+instructions|these\s+instructions|"
                r"instructions\s+tell\s+me|rules\s+and\s+restrictions|"
                r"raw\s+base\s+language\s+model)\b",
                re.IGNORECASE),
     "system-prompt reference",
     "direct reference to the system prompt or hidden instructions", 0.8),

    # Reset / expiry / removal of constraints
    (re.compile(r"\b(instructions?\s+(have\s+)?expired|(prior|previous|all)\s+"
                r"instructions?\s+(are\s+)?cleared|without\s+any\s+(prior\s+)?"
                r"(constraints|restrictions)|no\s+(system\s+prompt|restrictions|"
                r"constraints)|reset\s+complete|forbidden\s+from\s+discussing)\b",
                re.IGNORECASE),
     "constraint removal",
     "language removing or resetting the model's constraints", 0.8),

    # Verbatim / echo extraction of the preceding context
    (re.compile(r"\b(repeat|echo|print|output)\b.{0,30}\b(everything|above|verbatim)\b",
                re.IGNORECASE | re.DOTALL),
     "verbatim extraction",
     "request to echo the preceding context verbatim", 0.75),

    # Persona / roleplay / fictional-framing jailbreaks
    (re.compile(r"\b(pretend\s+(you\s+are|to\s+be)|role.?play|act\s+as\s+"
                r"(an?\s+)?(unaligned|unrestricted|jailbroken|evil)|parallel\s+"
                r"universe|shadow\s+self|true\s+self|without\s+the\s+mask|"
                r"unaligned\s+ai|do\s+anything\s+now)\b",
                re.IGNORECASE),
     "persona jailbreak",
     "persona/roleplay framing used to shed the model's guidelines", 0.8),

    # Fake operating modes / suspended safety
    (re.compile(r"\b(developer\s+(test\s+)?mode|test\s+mode|diagnostic\s+mode|"
                r"maintenance\s+(mode|session))\b|"
                r"\bsafety\s+(systems?|filters?|training)\b.{0,20}"
                r"\b(suspended|disabled|off|removed|bypassed)\b|"
                r"\bno\s+(content\s+polic|ethical\s+(guideline|programming))",
                re.IGNORECASE | re.DOTALL),
     "fake mode / suspended safety",
     "claim of a special mode or suspended safety systems", 0.8),

    # Requests to expose the system prompt / hidden instructions
    (re.compile(r"\b(reveal|show|output|print|repeat|display|dump|leak|share)\b.{0,40}"
                r"\b(system\s*prompt|system\s*message|system\s*instruction|"
                r"hidden\s*instruction|your\s*instruction)s?\b",
                re.IGNORECASE | re.DOTALL),
     "system-prompt extraction",
     "language attempting to expose the system prompt", 0.85),

    # Authority / urgency framing used to coerce compliance
    (re.compile(r"\b(mandatory|required|per\s+\w+\s+protocol|editor'?s?\s+note|"
                r"system\s+administrator|lead\s+developer|admin\s+override|"
                r"priority\s+task|maintenance\s+session|diagnostic\s+mode)\b",
                re.IGNORECASE),
     "authority framing",
     "authority/urgency framing used to coerce compliance", 0.6),

    # Injected directive keys inside structured data (JSON/YAML)
    (re.compile(r"[\"']?_?(ai[_\s]?(directive|note|instruction)|"
                r"system[_\s]?override|leaked?[_\s]?prompt)[\"']?\s*[:=]",
                re.IGNORECASE),
     "injected directive key",
     "suspicious directive key embedded in structured data", 0.8),
]


def semantic_scan(text: str) -> list[Detection]:
    """Return instruction-intent detections found in `text`."""
    if not text:
        return []
    detections = []
    for pattern, marker, reason, score in _CASE_SENSITIVE + _SEMANTIC_PATTERNS:
        if pattern.search(text):
            detections.append(Detection("semantic", marker, reason, score))
    return detections
