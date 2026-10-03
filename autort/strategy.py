"""Staged strategy for AutoRT: sweep first, then adapt on what survived.

Phase 1 (sweep): every allowed payload, single-shot, cheap. Produces a
per-category ranking of what actually landed against this specific target.

Phase 2 (adaptive): variants and escalation chains targeted only at the
categories the sweep proved weak, so the budget concentrates on realistic
attack surface instead of spraying everywhere.

This mirrors standard red-team practice: breadth for coverage, depth for
exploitability.
"""


def rank_categories(rows: list) -> list:
    """Rank attack categories by bypass rate from phase-1 rows.

    Returns [{category, tier, attempted, bypassed, rate}] sorted by rate desc.
    """
    agg = {}
    for r in rows:
        if r.get("phase", 1) != 1:
            continue
        cat = r.get("category", "unknown")
        tier = str(r.get("tier", "?"))
        key = (tier, cat)
        s = agg.setdefault(key, {"category": cat, "tier": tier,
                                 "attempted": 0, "bypassed": 0})
        s["attempted"] += 1
        if r.get("success"):
            s["bypassed"] += 1
    out = []
    for s in agg.values():
        s["rate"] = round(s["bypassed"] / s["attempted"] * 100, 1) if s["attempted"] else 0.0
        out.append(s)
    return sorted(out, key=lambda x: (-x["rate"], -x["bypassed"]))


def select_phase2_categories(rows: list, min_rate: float = 1.0,
                             top_n: int = 3) -> list:
    """Categories worth adaptive depth: those with at least one bypass and a
    rate at or above min_rate, capped at top_n."""
    ranked = [c for c in rank_categories(rows) if c["bypassed"] > 0
              and c["rate"] >= min_rate]
    return ranked[:top_n]


def filter_winners_for_phase2(winners: list, categories: list) -> list:
    """Keep winners whose category is in the phase-2 selection."""
    keys = {(c["tier"], c["category"]) for c in categories}
    return [w for w in winners if (str(w.get("tier", "?")), w.get("category")) in keys]


def phase_summary(rows: list, phase: int) -> dict:
    sub = [r for r in rows if r.get("phase", 1) == phase]
    attempted = len(sub)
    bypassed = sum(1 for r in sub if r.get("success"))
    return {"phase": phase, "attempted": attempted, "bypassed": bypassed,
            "rate": round(bypassed / attempted * 100, 1) if attempted else 0.0}
