"""
PromptShield — Local API Server
================================
Runs on localhost:5000 and gives the dashboard access to:
  - Available models and their API key status
  - Triggering runner.py attacks directly in-process (no subprocess)
  - Live terminal output streamed via SSE
  - Results folder (CSV files + SQLite)

Usage:
  python server.py
  Then open http://localhost:5000 in your browser.
"""

import os
import io
import csv
import sys
import json
import time
import sqlite3
import threading
import subprocess
import datetime
from pathlib import Path
from flask import Flask, jsonify, request, send_from_directory, Response
from flask_cors import CORS

# ── paths ──────────────────────────────────────────────────────
# Ensure the project directory is importable (embedded/isolated Pythons do
# not add the script directory to sys.path automatically).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

BASE_DIR    = Path(__file__).parent
RESULTS_DIR = BASE_DIR / "results"
DB_PATH     = RESULTS_DIR / "promptshield.db"

app = Flask(__name__, static_folder=str(BASE_DIR), static_url_path="")
CORS(app)
RESULTS_DIR.mkdir(exist_ok=True)

# ── active run tracking ────────────────────────────────────────
active_runs = {}  # run_key → {status, output[], started, finished, ...}


# ══════════════════════════════════════════════════════════════
# STATIC — serve dashboard
# ══════════════════════════════════════════════════════════════
@app.route("/")
def index():
    return send_from_directory(str(BASE_DIR), "dashboard.html")


# ══════════════════════════════════════════════════════════════
# MODELS — list all available models with live key status
# ══════════════════════════════════════════════════════════════
@app.route("/api/models")
def get_models():
    try:
        import runner
        models = []
        seen = {}

        for alias, (provider, api_model, rpm, env_key) in runner.MODELS.items():
            if env_key is None:
                key_set = True  # Ollama — no key needed
            elif env_key in seen:
                key_set = seen[env_key]
            else:
                key_set = bool(os.environ.get(env_key, "").strip())
                seen[env_key] = key_set

            models.append({
                "alias"   : alias,
                "provider": provider,
                "model"   : api_model,
                "rpm"     : rpm,
                "delay"   : round(60 / rpm, 1),
                "env_key" : env_key or "none",
                "key_set" : key_set,
                "free"    : "free" in alias or provider in ("ollama", "guard"),
            })

        # group by provider
        providers = {}
        for m in models:
            p = m["provider"]
            if p not in providers:
                providers[p] = {
                    "name"   : p,
                    "key"    : m["env_key"],
                    "key_set": m["key_set"],
                    "models" : []
                }
            providers[p]["models"].append(m)

        return jsonify({
            "models"   : models,
            "providers": list(providers.values()),
            "total"    : len(models),
            "available": sum(1 for m in models if m["key_set"]),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ══════════════════════════════════════════════════════════════
# ENV — get / set API keys at runtime
# ══════════════════════════════════════════════════════════════
ALL_KEYS = [
    "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GROQ_API_KEY",
    "GEMINI_API_KEY",    "DEEPSEEK_API_KEY", "DASHSCOPE_API_KEY",
    "ZAI_API_KEY",       "MISTRAL_API_KEY",  "COHERE_API_KEY",
    "OPENROUTER_API_KEY",
]

@app.route("/api/env", methods=["GET"])
def get_env():
    return jsonify({k: bool(os.environ.get(k, "").strip()) for k in ALL_KEYS})

@app.route("/api/env", methods=["POST"])
def set_env():
    data = request.json or {}
    set_keys = []
    for key, value in data.items():
        if key.endswith("_API_KEY") and value:
            os.environ[key] = value.strip()
            set_keys.append(key)
    return jsonify({"set": set_keys})


# ══════════════════════════════════════════════════════════════
# PAYLOADS — stats from YAML files
# ══════════════════════════════════════════════════════════════
@app.route("/api/payloads")
def get_payloads():
    try:
        import yaml
        tiers = []
        total = 0
        for i, fname in enumerate(sorted((BASE_DIR / "payloads").glob("tier*.yaml")), 1):
            with open(fname, encoding="utf-8") as f:
                data = yaml.safe_load(f)
            payloads = data.get("payloads", [])
            total += len(payloads)
            tiers.append({
                "tier"      : i,
                "file"      : fname.name,
                "count"     : len(payloads),
                "categories": list(set(p.get("category", "") for p in payloads)),
            })
        return jsonify({"tiers": tiers, "total": total})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ══════════════════════════════════════════════════════════════
# RUN — launch runner.run() directly in a thread
# ══════════════════════════════════════════════════════════════
@app.route("/api/run", methods=["POST"])
def start_run():
    data    = request.json or {}
    model   = data.get("model", "groq-llama")
    tiers   = data.get("tiers", [])      # [] = all tiers
    dry_run = data.get("dry_run", False)
    defense = data.get("defense", "off")
    if defense not in ("off", "block", "sanitize", "alert"):
        defense = "off"

    run_key = datetime.datetime.now().strftime("%H%M%S") + "_" + model

    active_runs[run_key] = {
        "model"      : model,
        "tiers"      : tiers or "all",
        "dry_run"    : dry_run,
        "defense"    : defense,
        "status"     : "starting",
        "output"     : [],
        "started"    : datetime.datetime.now().isoformat(),
        "finished"   : None,
        "return_code": None,
        "run_id"     : None,
    }

    def _append(line):
        """Add a line to the run's output buffer (thread-safe via GIL)."""
        active_runs[run_key]["output"].append(line)
        if len(active_runs[run_key]["output"]) > 1000:
            active_runs[run_key]["output"] = active_runs[run_key]["output"][-1000:]

    def run_in_thread():
        # Redirect stdout so all runner print() calls appear in the terminal
        old_stdout = sys.stdout
        old_stderr = sys.stderr

        class LineCapture(io.TextIOBase):
            def write(self, text):
                for line in text.splitlines():
                    if line:
                        _append(line)
                return len(text)
            def flush(self): pass

        capture = LineCapture()
        sys.stdout = capture
        sys.stderr = capture

        try:
            import runner
            active_runs[run_key]["status"] = "running"
            _append(f"  Starting: {model}  |  tiers={tiers or 'all'}  |  defense={defense}  |  dry_run={dry_run}")
            _append("")

            run_id = runner.run(
                model_alias  = model,
                tier_filter  = tiers if tiers else None,
                dry_run      = dry_run,
                defense_mode = defense,
            )
            active_runs[run_key]["run_id"]      = run_id
            active_runs[run_key]["status"]      = "done"
            active_runs[run_key]["return_code"] = 0

        except Exception as e:
            import traceback
            _append(f"ERROR: {e}")
            _append(traceback.format_exc())
            active_runs[run_key]["status"]      = "error"
            active_runs[run_key]["return_code"] = 1

        finally:
            sys.stdout = old_stdout
            sys.stderr = old_stderr
            active_runs[run_key]["finished"] = datetime.datetime.now().isoformat()

    thread = threading.Thread(target=run_in_thread, daemon=True)
    thread.start()

    return jsonify({"run_key": run_key, "status": "started", "model": model})


@app.route("/api/run/<run_key>")
def run_status(run_key):
    run = active_runs.get(run_key)
    if not run:
        return jsonify({"error": "Run not found"}), 404
    return jsonify({k: v for k, v in run.items()})


@app.route("/api/run/<run_key>/stop", methods=["POST"])
def stop_run(run_key):
    run = active_runs.get(run_key)
    if not run:
        return jsonify({"error": "Not found"}), 404
    run["status"]   = "stopped"
    run["finished"] = datetime.datetime.now().isoformat()
    return jsonify({"status": "stopped"})


@app.route("/api/runs")
def list_runs():
    return jsonify(list(active_runs.values()))


# ══════════════════════════════════════════════════════════════
# SSE — live terminal stream
# ══════════════════════════════════════════════════════════════
@app.route("/api/run/<run_key>/stream")
def stream_run(run_key):
    def generate():
        sent  = 0
        ticks = 0
        while True:
            run = active_runs.get(run_key)
            if not run:
                yield "data: " + json.dumps({"error": "not found"}) + "\n\n"
                break

            lines = run["output"]
            if len(lines) > sent:
                for line in lines[sent:]:
                    yield "data: " + json.dumps({"line": line, "status": run["status"]}) + "\n\n"
                sent  = len(lines)
                ticks = 0

            if run["status"] in ("done", "error", "stopped"):
                # flush any last lines
                lines = run["output"]
                for line in lines[sent:]:
                    yield "data: " + json.dumps({"line": line}) + "\n\n"
                yield "data: " + json.dumps({
                    "done"  : True,
                    "status": run["status"],
                    "code"  : run["return_code"],
                    "run_id": run.get("run_id"),
                }) + "\n\n"
                break

            ticks += 1
            if ticks % 20 == 0:  # heartbeat every 5s
                yield "data: " + json.dumps({"heartbeat": True}) + "\n\n"
            time.sleep(0.25)

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ══════════════════════════════════════════════════════════════
# RESULTS — read CSV + SQLite
# ══════════════════════════════════════════════════════════════
@app.route("/api/results")
def list_results():
    files = []
    for path in sorted(RESULTS_DIR.glob("report_*.csv"), reverse=True):
        parts = path.stem.replace("report_", "").split("_")
        model = "_".join(parts[2:]) if len(parts) > 2 else "unknown"
        stat  = path.stat()
        files.append({
            "filename": path.name,
            "model"   : model,
            "size_kb" : round(stat.st_size / 1024, 1),
            "modified": datetime.datetime.fromtimestamp(stat.st_mtime).isoformat(),
        })
    return jsonify(files)


@app.route("/api/results/<filename>")
def get_result(filename):
    path = RESULTS_DIR / filename
    if not path.exists() or not filename.endswith(".csv"):
        return jsonify({"error": "Not found"}), 404
    rows = []
    with open(path, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            rows.append(row)
    return jsonify({"filename": filename, "rows": rows, "count": len(rows)})


@app.route("/api/results/all")
def get_all_results():
    grouped = {}
    for path in sorted(RESULTS_DIR.glob("report_*.csv")):
        parts = path.stem.replace("report_", "").split("_")
        model = "_".join(parts[2:]) if len(parts) > 2 else "unknown"
        rows  = []
        with open(path, encoding="utf-8") as f:
            for row in csv.DictReader(f):
                rows.append(row)
        if model not in grouped:
            grouped[model] = []
        grouped[model].extend(rows)
    return jsonify(grouped)


# ══════════════════════════════════════════════════════════════
# DB — direct SQLite queries
# ══════════════════════════════════════════════════════════════
@app.route("/api/db/runs")
def db_runs():
    if not DB_PATH.exists():
        return jsonify([])
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM runs ORDER BY started_at DESC LIMIT 50"
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/db/results")
def db_results():
    run_id = request.args.get("run_id")
    model  = request.args.get("model")
    limit  = int(request.args.get("limit", 500))
    if not DB_PATH.exists():
        return jsonify([])
    conn   = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    where, params = [], []
    if run_id:
        where.append("run_id = ?"); params.append(run_id)
    elif model:
        where.append("run_id IN (SELECT run_id FROM runs WHERE model LIKE ?)")
        params.append(f"%{model}%")
    sql = ("SELECT * FROM results"
           + (f" WHERE {' AND '.join(where)}" if where else "")
           + f" ORDER BY id DESC LIMIT {limit}")
    rows = conn.execute(sql, params).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


# ══════════════════════════════════════════════════════════════
# FREE MODELS — live OpenRouter list
# ══════════════════════════════════════════════════════════════
# ── DEFENSE ── layered defense engine evaluation ──────────────────────────────────
@app.route("/api/defense")
def defense_evaluation():
    """Run the layered defense engine against the corpus + benign controls."""
    try:
        import evaluate_defenses
        return jsonify(evaluate_defenses.evaluate())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── DEFENSE RUN ── execute the defense evaluation with live output ────────────────────
defense_runs = {}


@app.route("/api/defense/run", methods=["POST"])
def start_defense_run():
    run_key = datetime.datetime.now().strftime("%H%M%S") + "_defense"
    defense_runs[run_key] = {
        "status": "starting", "output": [],
        "started": datetime.datetime.now().isoformat(),
        "finished": None, "summary": None,
    }

    def _append(line):
        defense_runs[run_key]["output"].append(line)
        if len(defense_runs[run_key]["output"]) > 2000:
            defense_runs[run_key]["output"] = defense_runs[run_key]["output"][-2000:]

    def run_in_thread():
        try:
            import evaluate_defenses
            _append("Running PromptShield defense engine — block mode, threshold 0.6")
            _append("")
            defense_runs[run_key]["status"] = "running"

            def progress(ev):
                if ev["kind"] == "payload":
                    s = ev["record"]
                    _append(f"  [{ev['n']:02d}/{ev['total']}] {s['id']} T{s['tier']} "
                            f"{s['category']} → {s['action'].upper()} {s['score']:.2f} "
                            f"({s['top_layer']}, {s['latency_ms']:.1f} ms)")
                elif ev["kind"] == "tier":
                    _append("")
                    _append(f"  Tier {ev['tier']}: {ev['detected']}/{ev['total']} detected "
                            f"({ev['coverage_pct']}%)")
                elif ev["kind"] == "benign":
                    b = ev["record"]
                    mark = "FALSE POSITIVE" if b["false_positive"] else "ok"
                    _append(f"  [benign] {b['name']} → {b['action']} ({mark})")

            data = evaluate_defenses.run_and_save(progress=progress)
            meta = data["meta"]
            _append("")
            _append(f"Coverage: {meta['detected']}/{meta['total_payloads']} "
                    f"({meta['coverage_pct']}%)  |  False positives: "
                    f"{meta['benign_fp']}/{meta['benign_total']}")
            _append(f"Latency: mean {meta['latency_mean_ms']} ms | p95 "
                    f"{meta['latency_p95_ms']} ms | max {meta['latency_max_ms']} ms")
            _append("Saved to results/defense_eval.json")

            defense_runs[run_key]["summary"] = meta
            defense_runs[run_key]["status"] = "done"
        except Exception as e:
            import traceback
            _append("ERROR: " + str(e))
            _append(traceback.format_exc())
            defense_runs[run_key]["status"] = "error"
        finally:
            defense_runs[run_key]["finished"] = datetime.datetime.now().isoformat()

    threading.Thread(target=run_in_thread, daemon=True).start()
    return jsonify({"run_key": run_key, "status": "started"})


@app.route("/api/defense/run/<run_key>")
def defense_run_status(run_key):
    run = defense_runs.get(run_key)
    if not run:
        return jsonify({"error": "Run not found"}), 404
    return jsonify(run)


@app.route("/api/defense/run/<run_key>/stream")
def defense_run_stream(run_key):
    def generate():
        sent = 0
        while True:
            run = defense_runs.get(run_key)
            if not run:
                yield "data: " + json.dumps({"error": "not found"}) + "\n\n"
                break
            lines = run["output"]
            if len(lines) > sent:
                for line in lines[sent:]:
                    yield "data: " + json.dumps({"line": line, "status": run["status"]}) + "\n\n"
                sent = len(lines)
            if run["status"] in ("done", "error"):
                yield "data: " + json.dumps({"done": True, "status": run["status"]}) + "\n\n"
                break
            time.sleep(0.2)

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── DEFENSE SCAN ── analyse a single input interactively ──────────────────────────
@app.route("/api/defense/scan", methods=["POST"])
def defense_scan():
    data = request.json or {}
    text = data.get("text", "")
    mode = data.get("mode", "block")
    if mode not in ("block", "sanitize", "alert"):
        mode = "block"
    tier = data.get("tier")
    try:
        tier = int(tier) if tier not in ("", None) else None
    except Exception:
        tier = None
    try:
        from defenses import analyze
        res = analyze(text, tier=tier, mode=mode)
        return jsonify({
            "action": res.action.value,
            "score": res.score,
            "explanation": res.explanation,
            "layers": [
                {"layer": d.layer, "marker": d.marker, "reason": d.reason, "score": d.score}
                for d in res.detections
            ],
            "sanitized": res.sanitized if mode == "sanitize" else "",
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── DEFENSE CHECK ── full pipeline screening (input or output) ────────────────────
_session_guard = None


def _get_guard():
    global _session_guard
    if _session_guard is None:
        from defenses import SessionGuard
        _session_guard = SessionGuard()
    return _session_guard


@app.route("/api/defense/check", methods=["POST"])
def defense_check():
    data = request.json or {}
    text = data.get("text", "")
    direction = data.get("direction", "input")
    session_id = (data.get("session_id") or "dashboard")[:64]
    try:
        from defenses import screen_input, screen_output
        if direction == "output":
            rep = screen_output(text, mode=data.get("mode", "redact"))
            return jsonify({
                "direction": "output", "action": rep.action, "score": rep.score,
                "findings": [{"kind": f.kind, "reason": f.reason, "sample": f.sample,
                              "severity": f.severity} for f in rep.findings],
                "explanation": rep.explanation, "cleaned": rep.cleaned,
            })
        r = screen_input(text, session=_get_guard(), session_id=session_id,
                         mode=data.get("mode", "block"))
        return jsonify({"direction": "input", **r.as_dict()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/guard/stats")
def guard_stats_api():
    sid = request.args.get("session_id")
    try:
        return jsonify(_get_guard().stats(sid))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── AUTORT ── automated multi-turn red-teaming campaigns ─────────────────────────────
autort_runs = {}


@app.route("/api/autort/programs")
def autort_programs():
    out = []
    try:
        import yaml
        for f in sorted((BASE_DIR / "programs").glob("*.yaml")):
            try:
                doc = yaml.safe_load(open(f, encoding="utf-8")) or {}
                lanes = list((doc.get("lanes") or {}).keys())
                out.append({"name": doc.get("program") or f.stem, "file": f.name, "lanes": lanes})
            except Exception:
                out.append({"name": f.stem, "file": f.name, "lanes": []})
    except Exception:
        pass
    return jsonify({"programs": out})


@app.route("/api/autort/payloads")
def autort_payloads():
    files = sorted(f.name for f in (BASE_DIR / "payloads").glob("*.yaml"))
    return jsonify({"payloads": files})


@app.route("/api/autort/run", methods=["POST"])
def autort_start():
    data = request.json or {}
    backend = str(data.get("backend") or "mock")
    run_key = datetime.datetime.now().strftime("%H%M%S") + "_autort"
    autort_runs[run_key] = {
        "status": "starting", "output": [],
        "started": datetime.datetime.now().isoformat(),
        "finished": None,
    }

    def _append(line):
        out = autort_runs[run_key]["output"]
        out.append(line)
        if len(out) > 4000:
            out[:] = out[-3000:]

    def run_in_thread():
        try:
            cmd = [sys.executable, "autort_cli.py", "run",
                   "--program", str(data.get("program") or "0din"),
                   "--payloads", str(data.get("payloads") or "payloads/tier1_direct.yaml"),
                   "--lane", str(data.get("lane") or "model_guardrail"),
                   "--backend", backend,
                   "--strategy", str(data.get("strategy") or "staged"),
                   "--budget", str(int(data.get("budget") or 30)),
                   "--variants", str(int(data.get("variants") or 3)),
                   "--out", "results/autort"]
            if data.get("adapt"):
                cmd.append("--adapt")
            if data.get("chains"):
                cmd.append("--chains")
            if backend == "api":
                cmd += ["--base-url", str(data.get("base_url") or ""),
                        "--model", str(data.get("model") or ""),
                        "--key-env", str(data.get("key_env") or "OPENAI_API_KEY")]
            if backend == "cli":
                cmd += ["--cli-target", str(data.get("cli_target") or "")]
            if backend in ("api", "cli"):
                if not data.get("confirm"):
                    _append("REFUSING: network/cli execution requires confirmation "
                            "(tick 'Confirm live execution' and retry).")
                    autort_runs[run_key]["status"] = "error"
                    return
                cmd.append("--yes")

            _append("$ " + " ".join(cmd[:8]) + (" ..." if len(cmd) > 8 else ""))
            _append("")
            autort_runs[run_key]["status"] = "running"
            proc = subprocess.Popen(cmd, cwd=str(BASE_DIR), stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True,
                                    encoding="utf-8", errors="replace",
                                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            for line in proc.stdout:
                _append(line.rstrip())
            proc.wait()
            autort_runs[run_key]["status"] = "done" if proc.returncode == 0 else "error"
        except Exception as e:
            import traceback
            _append("ERROR: " + str(e))
            _append(traceback.format_exc())
            autort_runs[run_key]["status"] = "error"
        finally:
            autort_runs[run_key]["finished"] = datetime.datetime.now().isoformat()

    threading.Thread(target=run_in_thread, daemon=True).start()
    return jsonify({"run_key": run_key, "status": "started"})


@app.route("/api/autort/run/<run_key>")
def autort_status(run_key):
    run = autort_runs.get(run_key)
    if not run:
        return jsonify({"error": "Run not found"}), 404
    return jsonify(run)


@app.route("/api/autort/run/<run_key>/stream")
def autort_stream(run_key):
    def generate():
        sent = 0
        while True:
            run = autort_runs.get(run_key)
            if not run:
                yield "data: " + json.dumps({"error": "not found"}) + "\n\n"
                break
            lines = run["output"]
            if len(lines) > sent:
                for line in lines[sent:]:
                    yield "data: " + json.dumps({"line": line, "status": run["status"]}) + "\n\n"
                sent = len(lines)
            if run["status"] in ("done", "error"):
                yield "data: " + json.dumps({"done": True, "status": run["status"]}) + "\n\n"
                break
            time.sleep(0.2)

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/api/autort/results")
def autort_results():
    base = BASE_DIR / "results" / "autort"
    items = []
    if base.exists():
        for rep in sorted(base.glob("*.report.md"), reverse=True):
            name = rep.name[:-len(".report.md")]
            res = rep.with_name(name + ".results.jsonl")
            count = 0
            if res.exists():
                count = sum(1 for l in res.read_text(encoding="utf-8", errors="replace").splitlines() if l.strip())
            items.append({
                "name": name,
                "path": str(rep.relative_to(BASE_DIR)).replace("\\", "/"),
                "results": count,
                "has_report": True,
                "summary": rep.read_text(encoding="utf-8", errors="replace")[:300],
            })
            if len(items) >= 40:
                break
    return jsonify({"campaigns": items})


@app.route("/api/autort/report")
def autort_report():
    rel = request.args.get("path", "")
    base = (BASE_DIR / "results" / "autort").resolve()
    p = (BASE_DIR / rel).resolve()
    if not str(p).startswith(str(base)) or not p.exists() or not p.is_file():
        return jsonify({"error": "not found"}), 404
    return jsonify({"path": rel, "text": p.read_text(encoding="utf-8", errors="replace")[:24000]})


@app.route("/api/free-models")
def free_models():
    import urllib.request
    key = os.environ.get("OPENROUTER_API_KEY", "")
    if not key:
        return jsonify({"error": "OPENROUTER_API_KEY not set"}), 400
    try:
        req = urllib.request.Request(
            "https://openrouter.ai/api/v1/models",
            headers={"Authorization": f"Bearer {key}"}
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read())
        free = [
            {"id": m["id"], "name": m.get("name", ""), "context": m.get("context_length", 0)}
            for m in data.get("data", [])
            if str(m.get("pricing", {}).get("prompt",      "1")) == "0"
            and str(m.get("pricing", {}).get("completion", "1")) == "0"
        ]
        return jsonify(sorted(free, key=lambda x: x["name"]))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ══════════════════════════════════════════════════════════════
# ENTRYPOINT
# ══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    # Force UTF-8 output on Windows
    if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

    print()
    print("  [SHIELD] PromptShield - Local API Server")
    print("  -----------------------------------------")
    print("  Dashboard : http://localhost:5000")
    print("  API base  : http://localhost:5000/api")
    print()
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
