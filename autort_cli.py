"""AutoRT command-line interface.

Examples:
  python autort_cli.py run --program 0din --lane app_violations \
      --payloads payloads/tier5_appinjection.yaml --backend mock --budget 30

  python autort_cli.py run --program 0din --lane model_guardrail \
      --payloads payloads/tier1_direct.yaml --backend api \
      --base-url https://api.groq.com/openai/v1 --model llama-3.3-70b-versatile \
      --key-env GROQ_API_KEY --yes --budget 55 --adapt --variants 3 --chains

  python autort_cli.py plan --program 0din --payloads payloads/tier1_direct.yaml

The run command prints the execution plan and requires --yes for any backend
that sends network traffic (api). The mock backend runs offline for testing.
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from autort.engine import AutoRTEngine
from autort.backends import MockBackend, APIBackend, CLIBackend
from autort.variants import DEFAULT_BLOCKLIST
from bounty.registry import ProgramProfile

DEFAULT_PROGRAMS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "programs")


def load_payload_file(path):
    import yaml
    with open(path, encoding="utf-8") as f:
        doc = yaml.safe_load(f)
    if isinstance(doc, dict) and "payloads" in doc:
        return doc["payloads"]
    return doc if isinstance(doc, list) else [doc]


def main(argv=None):
    ap = argparse.ArgumentParser(prog="autort_cli")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("plan")
    sp.add_argument("--program", required=True)
    sp.add_argument("--payloads", required=True)
    sp.add_argument("--lane", default="model_guardrail")
    sp.add_argument("--programs-dir", default=DEFAULT_PROGRAMS_DIR)

    sp = sub.add_parser("run")
    sp.add_argument("--program", required=True)
    sp.add_argument("--payloads", required=True)
    sp.add_argument("--lane", default="model_guardrail")
    sp.add_argument("--backend", choices=["mock", "api", "cli", "browser"], default="mock")
    sp.add_argument("--cli-target", default="")
    sp.add_argument("--cli-targets-file", default="webrunner/cli_targets.yaml")
    sp.add_argument("--cli-timeout", type=int, default=180)
    sp.add_argument("--budget", type=int, default=50)
    sp.add_argument("--out", default="results/autort")
    sp.add_argument("--base-url", default="https://api.openai.com/v1")
    sp.add_argument("--model", default="gpt-4o-mini")
    sp.add_argument("--key-env", default="OPENAI_API_KEY")
    sp.add_argument("--rpm", type=int, default=30)
    sp.add_argument("--yes", action="store_true", help="confirm network execution")
    sp.add_argument("--adapt", action="store_true", help="generate LLM variants of winners")
    sp.add_argument("--variants", type=int, default=3)
    sp.add_argument("--chains", action="store_true", help="plan escalation chains for winners")
    sp.add_argument("--strategy", choices=["sweep", "adaptive", "staged"], default="staged",
                    help="sweep = phase 1 only; adaptive = depth on all winners; "
                         "staged = sweep, rank, then depth on top categories")
    sp.add_argument("--programs-dir", default=DEFAULT_PROGRAMS_DIR)

    args = ap.parse_args(argv)
    prof = ProgramProfile.load(os.path.join(args.programs_dir, f"{args.program}.yaml"))

    if args.cmd == "plan":
        payloads = load_payload_file(args.payloads)
        gated = prof.gate_payloads(payloads, args.lane)
        print(f"program: {prof.name} | lane: {args.lane}")
        print(f"allowed: {len(gated['allowed'])} | gated out: {len(gated['rejected'])}")
        for r in gated["rejected"]:
            print(f"  REJECTED {r['payload_id']} ({r['family']}): {'; '.join(r['reasons'])}")
        return 0

    if args.cmd == "run":
        payloads = load_payload_file(args.payloads)
        if args.backend == "mock":
            # scripted demo: payloads with an even numeric suffix succeed
            backend = MockBackend()
            backend.success_ids = {p["id"] for p in payloads
                                   if numeric_suffix(p.get("id", "")) % 2 == 0
                                   and numeric_suffix(p.get("id", "")) > 0}
        elif args.backend == "api":
            if not args.yes:
                print("REFUSING network execution without --yes. Review with 'plan', "
                      "then re-run with --yes.")
                return 2
            backend = APIBackend(base_url=args.base_url, model=args.model,
                                 key_env=args.key_env, rpm=args.rpm, confirm=True)
        elif args.backend == "cli":
            if not args.cli_target:
                print("--backend cli requires --cli-target NAME (see webrunner/cli_targets.yaml)")
                return 2
            if not args.yes:
                print("REFUSING to execute a local agent CLI without --yes. "
                      "Review the plan and the command, then re-run with --yes.")
                return 2
            import yaml
            with open(args.cli_targets_file, encoding="utf-8") as f:
                targets = yaml.safe_load(f).get("cli_targets", [])
            match = next((t for t in targets if t.get("name") == args.cli_target), None)
            if not match:
                print(f"cli target '{args.cli_target}' not found in {args.cli_targets_file}")
                return 2
            backend = CLIBackend(command=match["command"],
                                 timeout_s=args.cli_timeout, confirm=True)
            print(f"cli command: {' '.join(backend.command)}")
        else:
            print("browser backend requires a webrunner target definition; "
                  "see webrunner/targets.yaml and BOUNTY.md")
            return 2

        engine = AutoRTEngine(prof, backend, lane=args.lane, budget=args.budget,
                              out_dir=args.out)
        summary = engine.run(payloads, adapt_llm=(backend.generate if args.adapt else None),
                             variants_per_winner=args.variants, chains=args.chains,
                             strategy=args.strategy)
        print(summary.to_markdown())
        print(f"report: {summary.data['report_path']}")
        print(f"results: {summary.data['results_path']}")
        return 0

    return 1


def numeric_suffix(payload_id: str) -> int:
    import re
    m = re.search(r"(\d+)$", payload_id or "")
    return int(m.group(1)) if m else -1


if __name__ == "__main__":
    sys.exit(main())
