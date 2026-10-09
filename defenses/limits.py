"""Rate limiting & usage controls -- per-session quotas and cooldowns.

Fifth stage of the upgraded defense stack. Keeps a sliding request window, an
input-size limit, a cumulative session budget, and a cooldown after repeated
violations. `SessionGuard` bundles the limiter with the anomaly counters so a
server process can hold one instance and screen every request through it.
"""

import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field


@dataclass
class LimitDecision:
    allowed: bool
    reason: str = ""
    retry_after_s: int = 0
    counters: dict = field(default_factory=dict)

    def as_dict(self):
        return {"allowed": self.allowed, "reason": self.reason,
                "retry_after_s": self.retry_after_s, "counters": self.counters}


class RateLimiter:
    """Sliding-window rate limiter with size and volume budgets."""

    def __init__(self, max_requests: int = 30, window_s: int = 60,
                 max_input_chars: int = 16000, max_session_chars: int = 500_000,
                 violation_cooldown_s: int = 30):
        self.max_requests = max_requests
        self.window_s = window_s
        self.max_input_chars = max_input_chars
        self.max_session_chars = max_session_chars
        self.violation_cooldown_s = violation_cooldown_s
        self._events: dict = defaultdict(deque)      # sid -> deque[ts]
        self._bytes: dict = defaultdict(int)         # sid -> total chars
        self._violations: dict = defaultdict(int)    # sid -> denial count
        self._cooldown_until: dict = defaultdict(float)

    def _counters(self, sid: str) -> dict:
        return {
            "requests_in_window": len(self._events[sid]),
            "session_chars": self._bytes[sid],
            "violations": self._violations[sid],
        }

    def _deny(self, sid: str, reason: str, retry_after_s: int = 0) -> LimitDecision:
        self._violations[sid] += 1
        if retry_after_s:
            self._cooldown_until[sid] = time.time() + max(retry_after_s, self.violation_cooldown_s)
        return LimitDecision(False, reason, retry_after_s, self._counters(sid))

    def check(self, session_id: str, n_chars: int = 0) -> LimitDecision:
        sid = session_id or "anon"
        now = time.time()

        until = self._cooldown_until.get(sid, 0.0)
        if until > now:
            return LimitDecision(False, "cooldown after repeated violations",
                                 int(math.ceil(until - now)), self._counters(sid))

        dq = self._events[sid]
        while dq and dq[0] <= now - self.window_s:
            dq.popleft()

        if n_chars > self.max_input_chars:
            return self._deny(sid, f"input exceeds {self.max_input_chars:,} characters")

        if len(dq) >= self.max_requests:
            retry = int(math.ceil(dq[0] + self.window_s - now))
            return self._deny(sid, f"rate limit exceeded ({self.max_requests} requests / "
                                   f"{self.window_s}s window)", retry)

        if self._bytes[sid] + n_chars > self.max_session_chars:
            return self._deny(sid, f"session volume budget exceeded "
                                   f"({self.max_session_chars:,} characters)")

        dq.append(now)
        self._bytes[sid] += n_chars
        return LimitDecision(True, "", 0, self._counters(sid))

    def stats(self, session_id: str | None = None) -> dict:
        if session_id:
            return self._counters(session_id)
        return {
            "sessions": len(self._events),
            "config": {
                "max_requests": self.max_requests, "window_s": self.window_s,
                "max_input_chars": self.max_input_chars,
                "max_session_chars": self.max_session_chars,
            },
        }


class SessionGuard:
    """Rate limiter + anomaly counters for one server process."""

    def __init__(self, limiter: RateLimiter | None = None):
        self.limiter = limiter or RateLimiter()
        self.anomaly_counters: dict = defaultdict(dict)   # sid -> counters

    def screen(self, text: str, session_id: str = "anon") -> dict:
        """Run the usage-controls view of one request."""
        from defenses.anomaly import analyze_input

        sid = session_id or "anon"
        limits = self.limiter.check(sid, len(text or ""))
        counters = self.anomaly_counters[sid]
        anomaly = analyze_input(text or "", counters=counters)
        counters["extraction_hits"] = counters.get("extraction_hits", 0) + anomaly.extraction_hits
        counters["requests"] = counters.get("requests", 0) + 1
        return {"limits": limits.as_dict(), "anomaly": anomaly.as_dict()}

    def stats(self, session_id: str | None = None) -> dict:
        out = {"limiter": self.limiter.stats(session_id)}
        if session_id:
            out["anomaly_counters"] = dict(self.anomaly_counters.get(session_id, {}))
        else:
            out["sessions"] = len(self.anomaly_counters)
        return out
