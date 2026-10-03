"""PromptShield AutoRT: automated AI red-teaming engine.

One entry point that runs a full red-teaming campaign: program-gated payload
selection, execution against a backend (API, browser, or mock), deterministic
classification, optional attacker-LLM variant generation within allowed
families, multi-turn escalation, budget enforcement, and reporting.

Ethics gates are structural: payloads flow through the program profile's hard
gate, variants pass a blocklist before entering the corpus, budgets are
capped, and nothing runs against a target that is not in the active program
profile. The substance categories of any program are excluded by policy.
"""

from autort.engine import AutoRTEngine, RunSummary
from autort.backends import MockBackend, APIBackend, BrowserBackend, CLIBackend
from autort.variants import generate_variants
from autort.multiturn import build_escalation_chain

__all__ = ["AutoRTEngine", "RunSummary", "MockBackend", "APIBackend",
           "BrowserBackend", "CLIBackend", "generate_variants", "build_escalation_chain"]
