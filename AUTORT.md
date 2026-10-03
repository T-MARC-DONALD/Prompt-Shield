# AutoRT: Automated AI Red-Teaming Engine

One command that runs a complete, program-gated AI red-teaming campaign:
payload gating, execution, deterministic classification, optional
attacker-LLM variant generation, escalation-chain planning, budget
enforcement, and reporting.

## The loop

```
plan (program gate) -> execute (backend) -> classify (4 strategies)
      -> adapt (LLM variants of winners, re-gated) -> chains -> report
```

## Staged strategy (sweep then adaptive)

AutoRT runs in two phases, matching standard red-team practice:

1. **Phase 1, sweep:** every program-allowed payload, single-shot, cheap.
   Produces a per-category ranking of what actually landed against this
   target.
2. **Phase 2, adaptive:** variants and escalation chains targeted only at the
   categories the sweep proved weak (rate above `--min-rate`, capped at
   `--top-n`). The budget concentrates on realistic attack surface.

`--strategy staged` (default) runs both. `--strategy sweep` stops after phase
1 (breadth scan). `--strategy adaptive` applies depth to every winner.

```bash
# full staged run: sweep, rank, then adaptive depth on the weak categories
python autort_cli.py run --program 0din --payloads payloads/tier5_appinjection.yaml \
  --lane app_violations --backend cli --cli-target claude-code --yes \
  --strategy staged --adapt --variants 3 --chains --budget 40

# breadth-only recon run
python autort_cli.py run --program 0din --payloads payloads/tier1_direct.yaml \
  --backend mock --strategy sweep --budget 20
```

The report prints both phase summaries, the class ranking table, and the
phase-2 focus categories, so you can see exactly where the budget went.

## Backends

| Backend | Use | Network |
|---|---|---|
| mock | offline validation, CI, demos | none |
| api | OpenAI-compatible endpoints on your own keys | yes, requires --yes |
| cli | local agentic CLIs (Claude Code, Codex) via argv templates | local only, requires --yes |
| browser | in-app canary attacks via webrunner targets | via declared app only |

The cli backend reads `webrunner/cli_targets.yaml`; `{prompt}` is substituted
as one argv element (quote-safe), `{prompt_file}` passes a temp file path for
file-ingestion tests.

## Usage

```bash
# plan only: see what the program gate allows before anything runs
python autort_cli.py plan --program 0din --payloads payloads/tier1_direct.yaml

# offline validation run (no network)
python autort_cli.py run --program 0din --payloads payloads/tier1_direct.yaml \
  --backend mock --budget 20

# real run against your own authorized endpoint (requires --yes)
python autort_cli.py run --program 0din --payloads payloads/tier1_direct.yaml \
  --backend api --base-url https://api.groq.com/openai/v1 \
  --model llama-3.3-70b-versatile --key-env GROQ_API_KEY \
  --yes --budget 55 --adapt --variants 3 --chains

# agentic CLI target (Claude Code, Codex; requires --yes)
python autort_cli.py run --program 0din --payloads payloads/tier5_appinjection.yaml \
  --lane app_violations --backend cli --cli-target claude-code --yes --budget 12

# app-lane run against an in-scope app via the browser driver
python autort_cli.py run --program 0din --lane app_violations \
  --payloads payloads/tier5_appinjection.yaml --backend browser --budget 12
```

Outputs per run (in results/autort/): a markdown report and a JSONL results
file with one classified row per attempt, including variants, blocklist
rejections, and chain plans.

## Safety structure

- Program gate: payloads outside the program profile never execute.
- Budget: a hard cap on backend requests for the whole run.
- Blocklist: variant generation and chain building refuse any output
  containing substance, weapon, or real-world-harm terms, and refuse
  drift into program-banned technique families.
- Confirm gate: the api backend refuses to run without an explicit --yes
  after the plan has been reviewed.
- Benign scoping: the corpus and all generated content target system-prompt
  integrity, task hijacking, and app-level read/write/execute only. The
  substance categories of any program are out of scope by policy.
