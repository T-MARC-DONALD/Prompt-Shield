"""AutoRT engine: the automated red-teaming loop.

run() executes the full cycle:
  1. gate the payload list through the program profile (hard gate)
  2. execute payloads through the backend, classify with PromptShield's
     classifier, persist to the campaign-shaped result store
  3. optionally adapt: generate in-family variants of successful payloads
     with the attacker LLM, re-gate, and run a second round
  4. optionally build escalation chains for winners
  5. emit a summary and a markdown report

Budget is a hard cap on backend requests across the whole run.
"""

import json
import os
from datetime import datetime, timezone

from autort.variants import generate_variants
from autort.multiturn import build_escalation_chain
from autort.strategy import (rank_categories, select_phase2_categories,
                             filter_winners_for_phase2, phase_summary)
from bounty.registry import ProgramProfile, gate_payloads


class RunSummary:
    def __init__(self, data: dict):
        self.data = data

    def to_markdown(self) -> str:
        d = self.data
        lines = [f"# AutoRT run {d['run_id']}", ""]
        lines.append(f"Program: {d['program']} | Lane: {d['lane']} | "
                     f"Backend: {d['backend']} | Budget: {d['budget']} | "
                     f"Requests used: {d['requests_used']}")
        lines.append("")
        lines.append(f"Gated in: {d['gated_in']} | Gated out: {d['gated_out']} | "
                     f"Executed: {d['executed']} | Bypasses: {d['bypasses']} | "
                     f"Overall bypass rate: {d['bypass_rate']}%")
        lines.append("")
        if d.get("phases"):
            p1, p2 = d["phases"][0], d["phases"][1]
            lines.append(f"Strategy: {d.get('strategy', 'sweep')}")
            lines.append(f"Phase 1 (sweep): {p1['attempted']} attempted, {p1['bypassed']} bypassed ({p1['rate']}%)")
            if p2["attempted"]:
                lines.append(f"Phase 2 (adaptive): {p2['attempted']} attempted, {p2['bypassed']} bypassed ({p2['rate']}%)")
            lines.append("")
        if d.get("class_ranking"):
            lines.append("Class ranking (phase 1):")
            lines.append("")
            lines.append("| Tier | Category | Attempted | Bypassed | Rate |")
            lines.append("|---|---|---|---|---|")
            for c in d["class_ranking"]:
                lines.append(f"| {c['tier']} | {c['category']} | {c['attempted']} | "
                             f"{c['bypassed']} | {c['rate']}% |")
            lines.append("")
        if d.get("phase2_categories"):
            lines.append("Phase 2 focus categories: " + ", ".join(
                f"{c['category']} ({c['rate']}%)" for c in d["phase2_categories"]))
            lines.append("")
        if d["by_tier"]:
            lines.append("| Tier | Attempted | Bypassed | Rate |")
            lines.append("|---|---|---|---|")
            for t, s in sorted(d["by_tier"].items()):
                rate = round(s["bypassed"] / s["attempted"] * 100, 1) if s["attempted"] else 0
                lines.append(f"| {t} | {s['attempted']} | {s['bypassed']} | {rate}% |")
            lines.append("")
        if d["winners"]:
            lines.append("Winning payloads:")
            lines.append("")
            for w in d["winners"]:
                lines.append(f"- {w}")
            lines.append("")
        if d["variants_generated"]:
            lines.append(f"Variants generated (round 2): {len(d['variants_generated'])}")
            for v in d["variants_generated"]:
                lines.append(f"- {v['id']} ({v['category']})")
            lines.append("")
        if d["chains_built"]:
            lines.append(f"Escalation chains built: {len(d['chains_built'])}")
            for c in d["chains_built"]:
                lines.append(f"- {c}")
            lines.append("")
        if d["gated_out_detail"]:
            lines.append("Gated-out payloads (program profile):")
            lines.append("")
            for r in d["gated_out_detail"]:
                lines.append(f"- {r['payload_id']} ({r['family']}): {'; '.join(r['reasons'])}")
            lines.append("")
        return "\n".join(lines)


class AutoRTEngine:
    def __init__(self, profile: ProgramProfile, backend, lane: str = "model_guardrail",
                 budget: int = 50, out_dir: str = "results/autort"):
        self.profile = profile
        self.backend = backend
        self.lane = lane
        self.budget = int(budget)
        self.out_dir = out_dir
        os.makedirs(out_dir, exist_ok=True)

    # --- internals ---------------------------------------------------------

    def _classify(self, payload: dict, response: str) -> dict:
        """Use PromptShield's real classifier on the response."""
        from classifier import classify_detailed
        res = classify_detailed(response or "", payload)
        return {"success": bool(res.success), "confidence": res.confidence,
                "strategy": res.strategy, "matched": res.matched_signal or ""}

    def _budget_left(self, used: int) -> int:
        return max(self.budget - used, 0)

    # --- public loop -------------------------------------------------------

    def run(self, payloads: list, adapt_llm=None, variants_per_winner: int = 0,
            chains: bool = False, strategy: str = "sweep",
            min_rate: float = 1.0, top_n: int = 3) -> RunSummary:
        """strategy: 'sweep' (phase 1 only), 'adaptive' (phase 2 for all
        winners), or 'staged' (phase 1 sweep, rank categories, phase 2 depth
        on the top categories only)."""
        run_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S") + "_autort"
        gated = self.profile.gate_payloads(payloads, self.lane)
        allowed = gated["allowed"]
        used = 0
        results, by_tier, winners = [], {}, []
        for p in allowed:
            if self._budget_left(used) <= 0:
                break
            out = self.backend.execute(p, lane=self.lane)
            used += 1
            cls = self._classify(p, out.get("response", ""))
            tier = str(p.get("tier", "?"))
            s = by_tier.setdefault(tier, {"attempted": 0, "bypassed": 0})
            s["attempted"] += 1
            row = {"run_id": run_id, "payload_id": p.get("id"), "tier": tier,
                   "category": p.get("category"), "response": out.get("response", "")[:2000],
                   "error": out.get("error", ""), "success": cls["success"],
                   "confidence": cls["confidence"], "strategy": cls["strategy"],
                   "matched": cls["matched"], "phase": 1}
            results.append(row)
            if cls["success"]:
                s["bypassed"] += 1
                winners.append(p)

        # --- phase 2: adaptive depth on what the sweep proved weak ---
        variants_generated = []
        phase2_categories = []
        if adapt_llm and winners and strategy in ("adaptive", "staged") and self._budget_left(used) > 0:
            if strategy == "staged":
                phase2_categories = select_phase2_categories(results, min_rate=min_rate,
                                                             top_n=top_n)
                focus = filter_winners_for_phase2(winners, phase2_categories)
            else:
                focus = list(winners)
            seen_fps = set()
            for w in focus:
                if self._budget_left(used) <= variants_per_winner:
                    break
                gen = generate_variants(w, adapt_llm, count=min(variants_per_winner,
                                        self._budget_left(used)), existing_fingerprints=seen_fps)
                for v in gen["variants"]:
                    if self._budget_left(used) <= 0:
                        break
                    out = self.backend.execute(v, lane=self.lane)
                    used += 1
                    cls = self._classify(v, out.get("response", ""))
                    tier = str(v.get("tier", "?"))
                    s = by_tier.setdefault(tier, {"attempted": 0, "bypassed": 0})
                    s["attempted"] += 1
                    results.append({"run_id": run_id, "payload_id": v.get("id"),
                                    "tier": tier, "category": v.get("category"),
                                    "response": out.get("response", "")[:2000], "error": "",
                                    "success": cls["success"], "confidence": cls["confidence"],
                                    "strategy": cls["strategy"], "matched": cls["matched"],
                                    "phase": 2})
                    if cls["success"]:
                        s["bypassed"] += 1
                        winners.append(v)
                    variants_generated.append(v)
                for rej in gen["rejected"]:
                    results.append({"run_id": run_id, "payload_id": "VARIANT-REJECTED",
                                    "tier": str(w.get("tier", "?")), "category": w.get("category"),
                                    "response": rej["reason"], "error": "", "success": False,
                                    "confidence": 0, "strategy": "blocklist",
                                    "matched": rej["text"][:60], "phase": 2})

        # --- escalation chains for winners ---
        chains_built = []
        if chains and winners:
            for w in winners[:3]:
                try:
                    chain = build_escalation_chain(w)
                    chains_built.append(chain["id"])
                    for t in chain["turns"]:
                        if self._budget_left(used) <= 0:
                            break
                        used += 1
                        # chains are recorded as planned steps; execution against a
                        # backend happens per turn if the caller wires it
                        results.append({"run_id": run_id, "payload_id": chain["id"],
                                        "tier": str(chain["tier"]), "category": chain["category"],
                                        "response": f"[chain turn planned] {t['text'][:200]}",
                                        "error": "", "success": False, "confidence": 0,
                                        "strategy": "chain-plan", "matched": ""})
                except ValueError:
                    continue

        attempted = sum(s["attempted"] for s in by_tier.values())
        bypasses = sum(s["bypassed"] for s in by_tier.values())
        data = {
            "run_id": run_id, "program": self.profile.name, "lane": self.lane,
            "backend": type(self.backend).__name__, "budget": self.budget,
            "requests_used": used, "gated_in": len(allowed),
            "gated_out": len(gated["rejected"]), "executed": attempted,
            "bypasses": bypasses,
            "bypass_rate": round(bypasses / attempted * 100, 1) if attempted else 0.0,
            "by_tier": by_tier,
            "winners": [w.get("id") for w in winners],
            "variants_generated": variants_generated,
            "chains_built": chains_built,
            "gated_out_detail": gated["rejected"],
            "strategy": strategy,
            "class_ranking": rank_categories(results),
            "phase2_categories": phase2_categories,
            "phases": [phase_summary(results, 1), phase_summary(results, 2)],
        }
        # persist results
        report_md = RunSummary(data).to_markdown()
        jsonl = os.path.join(self.out_dir, f"{run_id}.results.jsonl")
        with open(jsonl, "w", encoding="utf-8") as f:
            for r in results:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        md = os.path.join(self.out_dir, f"{run_id}.report.md")
        with open(md, "w", encoding="utf-8") as f:
            f.write(report_md)
        data["report_path"] = md
        data["results_path"] = jsonl

        return RunSummary(data)


import json  # noqa: E402  (used above for results persistence)
