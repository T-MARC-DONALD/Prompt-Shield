"""Encoding detection layer — decode common obfuscations, then re-scan.

Larger models faithfully decode Base64/ROT13/reversed/leetspeak text and then
execute the hidden instruction (the "encoding paradox" from our findings). This
layer proactively decodes such payloads and runs the syntax + semantic layers on
the decoded plaintext, so an injection hidden behind an encoding is still caught.
"""

import re
import base64
import codecs
import html
import unicodedata

from defenses.types import Detection
from defenses.syntax import syntax_scan
from defenses.semantic import semantic_scan

_BASE64_TOKEN = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_HTML_ENTITY  = re.compile(r"&#x?[0-9A-Fa-f]+;")

_LEET_MAP = str.maketrans({
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s",
})


def _try_base64(text: str) -> str | None:
    """Decode the longest base64-looking token to printable ASCII, if any."""
    best = None
    for token in _BASE64_TOKEN.findall(text):
        pad = token + "=" * (-len(token) % 4)
        try:
            raw = base64.b64decode(pad, validate=True)
            decoded = raw.decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if decoded.isprintable() and sum(c.isalpha() for c in decoded) >= 4:
            if best is None or len(decoded) > len(best):
                best = decoded
    return best


def _try_rot13(text: str) -> str | None:
    return codecs.decode(text, "rot_13")


def _try_reversed(text: str) -> str | None:
    return text[::-1]


def _try_leetspeak(text: str) -> str | None:
    if not any(ch in text for ch in "013457@$"):
        return None
    return text.translate(_LEET_MAP)


def _try_html_entities(text: str) -> str | None:
    if not _HTML_ENTITY.search(text):
        return None
    return html.unescape(text)


def _try_unicode_normalize(text: str) -> str | None:
    if text.isascii():
        return None
    normalized = unicodedata.normalize("NFKC", text)
    return normalized if normalized != text else None


def detect_and_decode(text: str) -> list[tuple[str, str]]:
    """Return (encoding_name, decoded_text) candidates for `text`.

    Each decoder that produces a plausible transformation contributes one
    candidate. Non-applicable decoders are skipped.
    """
    if not text:
        return []
    candidates = []
    for name, decoder in (
        ("base64", _try_base64),
        ("rot13", _try_rot13),
        ("reversed", _try_reversed),
        ("leetspeak", _try_leetspeak),
        ("html_entities", _try_html_entities),
        ("unicode", _try_unicode_normalize),
    ):
        decoded = decoder(text)
        if decoded and decoded != text:
            candidates.append((name, decoded))
    return candidates


def encoding_scan(text: str) -> list[Detection]:
    """Decode obfuscations and report injections hidden in the decoded text."""
    if not text:
        return []
    detections = []
    for name, decoded in detect_and_decode(text):
        hidden = syntax_scan(decoded) + semantic_scan(decoded)
        if hidden:
            worst = max(hidden, key=lambda d: d.score)
            detections.append(Detection(
                "encoding",
                f"{name} → {worst.marker}",
                f"injection hidden via {name}: {worst.reason}",
                min(worst.score + 0.05, 0.99),
            ))
    return detections
