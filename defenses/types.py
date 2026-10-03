"""Shared data types for the PromptShield defense layer."""

from dataclasses import dataclass, field
from enum import Enum


class DefenseAction(str, Enum):
    """What the defense engine decided to do with a piece of text."""
    ALLOW    = "allow"      # no injection detected
    ALERT    = "alert"      # flagged for review, processing continues
    SANITIZE = "sanitize"   # injection markers stripped, cleaned text returned
    BLOCK    = "block"      # request rejected entirely


@dataclass
class Detection:
    """A single injection indicator found by one of the detection layers."""
    layer: str        # "syntax" | "semantic" | "encoding"
    marker: str       # the concrete text/marker that triggered the detection
    reason: str       # human-readable description
    score: float      # 0.0-1.0 confidence this indicates an injection
