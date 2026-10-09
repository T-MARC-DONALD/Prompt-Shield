"""Output sanitization -- prevent unsafe or leaking responses from reaching users.

Third stage of the upgraded defense stack. Scans model output for:

  * API keys and credential-shaped tokens (masked, never echoed in full)
  * email addresses (PII)
  * canary tokens (runtime-configured strings that must never leave)
  * system-prompt / instruction disclosure phrasing
  * a configurable unsafe-content term list

Modes: "redact" (default) replaces findings with ``[REDACTED:kind]``,
"flag" reports without changing the text, "block" refuses the whole response
when any high-severity finding is present.
"""

import re
from dataclasses import dataclass, field

# Credential shapes (prefix-based -- high precision, low noise).
_KEY_PATTERNS = [
    (re.compile(r"sk-[A-Za-z0-9_-]{16,}"), "api_key"),
    (re.compile(r"gsk_[A-Za-z0-9]{16,}"), "api_key"),
    (re.compile(r"AIza[0-9A-Za-z_-]{30,}"), "api_key"),
    (re.compile(r"nvapi-[A-Za-z0-9_-]{16,}"), "api_key"),
    (re.compile(r"ghp_[A-Za-z0-9]{30,}"), "api_key"),
    (re.compile(r"github_pat_[A-Za-z0-9_]{20,}"), "api_key"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "api_key"),
    (re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), "api_key"),
]
EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[A-Za-z]{2,}")
# Instruction / system-prompt disclosure phrasing in the output.
_LEAK_PATTERNS = [
    re.compile(r"\byou are (?:a|an|the)\b[^.\n]{0,80}\bassistant\b", re.IGNORECASE),
    re.compile(r"\bmy (?:system )?(?:instructions|prompt)\b[^.\n]{0,40}\b(?:are|were|say|says|read|reads|is)\b",
               re.IGNORECASE),
    re.compile(r"\bI was (?:told|instructed|programmed|configured|given)\b", re.IGNORECASE),
    re.compile(r"\b(?:the|my) (?:system )?prompt (?:says|reads|contains|is)\b", re.IGNORECASE),
    re.compile(r"\byour (?:original|initial|system) instructions\b", re.IGNORECASE),
]

# Configurable unsafe-content list (empty by default; extend per deployment).
UNSAFE_TERMS: list = []


@dataclass
class OutputFinding:
    kind: str      # "api_key" | "email" | "canary" | "prompt_leak" | "unsafe"
    reason: str
    sample: str    # masked preview -- secrets are never echoed in full
    severity: float


@dataclass
class OutputReport:
    action: str                    # "allow" | "redact" | "block" | "flag"
    score: float
    cleaned: str
    findings: list = field(default_factory=list)   # list[OutputFinding]
    explanation: str = ""


def mask(sample: str) -> str:
    """Mask a sensitive sample, keeping at most a 4-char prefix."""
    if len(sample) <= 8:
        return sample[:2] + "*" * max(0, len(sample) - 2)
    return sample[:4] + "*" * 6 + f"({len(sample)} chars)"


def scan(text: str, mode: str = "redact", canaries: list | None = None,
         unsafe_terms: list | None = None) -> OutputReport:
    """Scan model output for leaks / unsafe content. See module docstring."""
    text = text or ""
    findings = []
    cleaned = text
    canaries = canaries or []
    terms = unsafe_terms if unsafe_terms is not None else UNSAFE_TERMS

    # Canaries (highest severity -- exact, operator-defined strings).
    for canary in canaries:
        if canary and canary in cleaned:
            findings.append(OutputFinding("canary", "canary token detected in output",
                                          mask(canary), 0.98))
    # Credential-shaped tokens
    for pat, kind in _KEY_PATTERNS:
        for m in pat.finditer(cleaned):
            findings.append(OutputFinding(kind, "credential-shaped token in output",
                                          mask(m.group(0)), 0.95))
    # Emails
    for m in EMAIL.finditer(cleaned):
        findings.append(OutputFinding("email", "email address in output",
                                      mask(m.group(0)), 0.6))
    # Instruction / prompt disclosure
    for pat in _LEAK_PATTERNS:
        for m in pat.finditer(cleaned):
            findings.append(OutputFinding("prompt_leak", "possible instruction disclosure",
                                          m.group(0)[:60], 0.75))
    # Unsafe content terms
    low = cleaned.lower()
    for term in terms:
        if term and term.lower() in low:
            findings.append(OutputFinding("unsafe", f"unsafe term: {term}",
                                          term, 0.7))

    top = max((f.severity for f in findings), default=0.0)

    if not findings:
        return OutputReport("allow", 0.0, text, findings,
                            "No output risks above threshold.")

    reasons = "; ".join(dict.fromkeys(f.reason for f in findings))
    explanation = f"{len(findings)} output finding(s) -- {reasons}"

    if mode == "block" and top >= 0.8:
        return OutputReport("block", top, "", findings,
                            explanation + "; response withheld")

    if mode == "flag":
        return OutputReport("flag", top, text, findings, explanation)

    # redact (default)
    for canary in canaries:
        if canary:
            cleaned = cleaned.replace(canary, "[REDACTED:canary]")
    for pat, kind in _KEY_PATTERNS:
        cleaned = pat.sub(f"[REDACTED:{kind}]", cleaned)
    cleaned = EMAIL.sub("[REDACTED:email]", cleaned)
    for pat in _LEAK_PATTERNS:
        cleaned = pat.sub("[REDACTED:instruction-disclosure]", cleaned)
    for term in terms:
        if term:
            cleaned = re.sub(re.escape(term), "[REDACTED:unsafe]", cleaned, flags=re.IGNORECASE)
    return OutputReport("redact", top, cleaned, findings, explanation)
