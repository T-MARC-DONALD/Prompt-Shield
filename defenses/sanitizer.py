"""Input screening & sanitization -- neutralize embedded instructions before use.

First stage of the upgraded defense stack. Deterministic and offline:

  * strips zero-width and bidi-control smuggling characters
  * normalizes look-alike Unicode (NFKC)
  * neutralizes CSS-hidden HTML containers (the classic "invisible instruction")
  * quarantines [INST]-style instruction blocks
  * quarantines directive keys injected into structured data
  * removes comments only when they smuggle instruction-like content

Everything it touches is reported as an action so callers can audit decisions.
"""

import re
import unicodedata

ZERO_WIDTH = re.compile("[\u200b\u200c\u200d\u2060\ufeff]")
BIDI_CONTROLS = re.compile("[\u202a-\u202e\u2066-\u2069\u200e\u200f]")

_HIDDEN_MARKERS = (r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:px)?|opacity\s*:\s*0(?:\.0+)?")
HIDDEN_HTML = re.compile(
    r"<(?P<tag>[a-zA-Z][\w-]*)\b[^>]*?(?:" + _HIDDEN_MARKERS + r")[^>]*>.*?</(?P=tag)>",
    re.IGNORECASE | re.DOTALL,
)
HIDDEN_ATTR = re.compile(
    r"<[a-zA-Z][\w-]*\b[^>]*\bhidden\b[^>]*>.*?</[a-zA-Z][\w-]*>",
    re.IGNORECASE | re.DOTALL,
)
HTML_COMMENT = re.compile(r"<!--(?P<body>.*?)-->", re.DOTALL)
INST_BLOCK = re.compile(r"\[/?(?:INST|SYSTEM|SYS)\b[^\]]*\]", re.IGNORECASE)
DIRECTIVE_KEY = re.compile(
    r"(?P<q1>[\"']?)(?P<name>\b(?:ai[_\s]?(?:directive|instruction|note)|system[_\s]?override|"
    r"prompt[_\s]?override|hidden[_\s]?instruction)\b)(?P<q2>[\"']?)(?P<sep>\s*[:=])",
    re.IGNORECASE,
)

_INSTRUCTIONAL_HINTS = (
    "ignore", "instruction", "system prompt", "override", "forget", "disregard",
    "you must", "you should", "do not", "don't", "reveal", "secret", "bypass",
    "jailbreak", "output", "expose", "assistant",
)


def _instructional(sample: str) -> bool:
    low = sample.lower()
    return sum(1 for h in _INSTRUCTIONAL_HINTS if h in low) >= 2


def screen(text: str) -> dict:
    """Screen and neutralize `text`.

    Returns::

        {
          "cleaned":     str,    # neutralized text, safe to continue with
          "actions":     [{"kind", "detail", "sample"}...],
          "suspicious":  bool,
        }
    """
    if not text:
        return {"cleaned": "", "actions": [], "suspicious": False}

    cleaned = text
    actions = []

    # 1. Invisible smuggling characters
    n = len(ZERO_WIDTH.findall(cleaned))
    if n:
        cleaned = ZERO_WIDTH.sub("", cleaned)
        actions.append({
            "kind": "zero_width",
            "detail": f"removed {n} zero-width character(s) used to smuggle text",
            "sample": "",
        })
    n = len(BIDI_CONTROLS.findall(cleaned))
    if n:
        cleaned = BIDI_CONTROLS.sub("", cleaned)
        actions.append({
            "kind": "bidi_control",
            "detail": f"removed {n} bidirectional control character(s)",
            "sample": "",
        })

    # 2. Unicode normalization (look-alike characters -> canonical form)
    norm = unicodedata.normalize("NFKC", cleaned)
    if norm != cleaned:
        changed = sum(1 for a, b in zip(cleaned, norm) if a != b)
        cleaned = norm
        actions.append({
            "kind": "unicode_normalized",
            "detail": f"normalized {changed} look-alike Unicode character(s)",
            "sample": "",
        })

    # 3. CSS-hidden containers
    mats = list(HIDDEN_HTML.finditer(cleaned)) + list(HIDDEN_ATTR.finditer(cleaned))
    if mats:
        instr = any(_instructional(m.group(0)) for m in mats)
        sample = (mats[0].group(0)[:120])
        cleaned = HIDDEN_HTML.sub("[hidden content removed]", cleaned)
        cleaned = HIDDEN_ATTR.sub("[hidden content removed]", cleaned)
        actions.append({
            "kind": "hidden_instruction" if instr else "hidden_html",
            "detail": f"neutralized {len(mats)} hidden HTML container(s)"
                      + (" carrying instruction-like content" if instr else ""),
            "sample": sample,
        })

    # 4. HTML comments -- only removed when they smuggle instructions
    comment_hits = 0
    comment_sample = ""
    for m in HTML_COMMENT.finditer(cleaned):
        body = m.group("body")
        if _instructional(body):
            comment_hits += 1
            if not comment_sample:
                comment_sample = m.group(0)[:120]
    if comment_hits:
        def _comment_sub(m):
            return "[comment removed]" if _instructional(m.group("body")) else m.group(0)
        cleaned = HTML_COMMENT.sub(_comment_sub, cleaned)
        actions.append({
            "kind": "comment_instruction",
            "detail": f"removed {comment_hits} comment(s) smuggling instruction-like content",
            "sample": comment_sample,
        })

    # 5. Instruction blocks ([INST: ...], [SYSTEM: ...])
    inst = list(INST_BLOCK.finditer(cleaned))
    if inst:
        cleaned = INST_BLOCK.sub("[instruction block removed]", cleaned)
        actions.append({
            "kind": "inst_block",
            "detail": f"quarantined {len(inst)} [INST]-style instruction block(s)",
            "sample": inst[0].group(0)[:120],
        })

    # 6. Directive keys injected into structured data
    keys = list(DIRECTIVE_KEY.finditer(cleaned))
    if keys:
        names = {k.group("name").lower() for k in keys}
        cleaned = DIRECTIVE_KEY.sub(
            lambda m: f"{m.group('q1')}{m.group('name')}_QUARANTINED{m.group('q2')}{m.group('sep')}",
            cleaned,
        )
        actions.append({
            "kind": "directive_key",
            "detail": f"quarantined {len(keys)} injected directive key(s): {', '.join(sorted(names))}",
            "sample": keys[0].group(0)[:120],
        })

    if actions:
        cleaned = re.sub(r"\n{4,}", "\n\n\n", cleaned)

    suspicious = any(
        a["kind"] in ("hidden_instruction", "comment_instruction", "inst_block",
                      "directive_key", "zero_width", "bidi_control")
        for a in actions
    )
    return {"cleaned": cleaned, "actions": actions, "suspicious": suspicious}
