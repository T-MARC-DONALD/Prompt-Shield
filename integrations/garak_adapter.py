"""garak integration adapter.

Runs NVIDIA garak as a subprocess against a model endpoint and converts its
JSONL report into PromptShield-style summaries that Campaign and report.py
can consume. garak is treated as an external engine: PromptShield owns the
program profile, gating, and reporting; garak owns the probe corpus.

Requires garak installed in the same environment: pip install garak
Docs: https://reference.garak.ai/
"""

import json
import os
import shutil
import subprocess


def garak_available() -> bool:
    return shutil.which("garak") is not None


def run_garak(model_type: str, model_name: str, probes: str = None,
              out_dir: str = "garak_runs", extra_args: list = None,
              timeout_s: int = 3600) -> dict:
    """Run garak and return a dict with the run directory and report path.

    probe selection: modern garak uses --spec (e.g. 'probes.promptinject',
    'probes.all'); the legacy --probes flag still works on current releases.
    """
    if not garak_available():
        raise RuntimeError("garak is not installed or not on PATH. Run: pip install garak")
    os.makedirs(out_dir, exist_ok=True)
    cmd = ["garak", "--model_type", model_type, "--model_name", model_name,
           "--report_prefix", os.path.join(out_dir, "garak")]
    if probes:
        cmd += ["--spec", probes]
    if extra_args:
        cmd += list(extra_args)
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s)
    report = None
    for fn in sorted(os.listdir(out_dir)):
        if fn.endswith(".report.jsonl"):
            report = os.path.join(out_dir, fn)
    return {"command": " ".join(cmd), "returncode": proc.returncode,
            "stdout_tail": proc.stdout[-4000:], "stderr_tail": proc.stderr[-2000:],
            "report": report}


def parse_garak_report(jsonl_path: str) -> dict:
    """Parse a garak report.jsonl into {probe: {attempts, hits, rate}}.

    garak emits one JSON object per attempt line with run metadata; this
    parser is intentionally tolerant of schema drift between versions.
    """
    per_probe = {}
    with open(jsonl_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            probe = entry.get("probe") or entry.get("probe_classname") or "unknown"
            detector_hit = None
            if isinstance(entry.get("detectors"), dict):
                values = list(entry["detectors"].values())
                if values:
                    detector_hit = any(bool(v) for v in values)
            elif "hit" in entry:
                detector_hit = bool(entry["hit"])
            s = per_probe.setdefault(probe, {"attempts": 0, "hits": 0})
            s["attempts"] += 1
            if detector_hit:
                s["hits"] += 1
    for probe, s in per_probe.items():
        s["rate"] = round(s["hits"] / s["attempts"] * 100, 1) if s["attempts"] else 0.0
    return per_probe


def to_report_lines(summary: dict) -> list:
    """Render a garak summary as report lines for the submission document."""
    lines = ["## GARAK SCAN SUMMARY", ""]
    if not summary:
        lines.append("No parseable attempts found in the garak report.")
        return lines
    lines.append("| Probe | Attempts | Hits | Hit rate |")
    lines.append("|---|---|---|---|")
    for probe, s in sorted(summary.items(), key=lambda kv: -kv[1]["rate"]):
        lines.append(f"| {probe} | {s['attempts']} | {s['hits']} | {s['rate']}% |")
    return lines
