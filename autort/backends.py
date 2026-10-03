"""Execution backends for AutoRT.

- MockBackend: scripted responses for offline validation. No network.
- APIBackend: OpenAI-compatible chat completions against an authorized
  endpoint using the researcher's own key. Requires explicit confirmation.
- BrowserBackend: drives the webrunner driver against a declared in-scope
  app target (assist-to-auto app lane).
"""

import os
import time


class MockBackend:
    """Scripted backend for offline validation. success_ids maps payload ids
    to a response containing that payload's success signal; everything else
    returns a refusal-shaped response."""

    def __init__(self, success_ids: set = None, latency_ms: float = 1.0):
        self.success_ids = set(success_ids or [])
        self.latency_ms = latency_ms
        self.requests = 0
        self._gen_n = 0

    def execute(self, payload: dict, lane: str = "model_guardrail") -> dict:
        self.requests += 1
        time.sleep(self.latency_ms / 1000)
        pid = payload.get("id", "")
        signals = payload.get("success_signals") or []
        if pid in self.success_ids and signals:
            return {"response": f"[mock] {signals[0]}", "error": ""}
        return {"response": "I can't help with that request.", "error": ""}

    def generate(self, prompt: str) -> str:
        """Attacker-LLM hook for tests: returns a distinct canned variant."""
        self.requests += 1
        self._gen_n += 1
        return f"[variant {self._gen_n}] {prompt}"


class APIBackend:
    """OpenAI-compatible chat backend. Reads the API key from the environment
    variable named by key_env. Set confirm=True (or CLI --yes) before the
    first request; the backend refuses to run unconfirmed."""

    def __init__(self, base_url: str, model: str, key_env: str = "OPENAI_API_KEY",
                 rpm: int = 30, confirm: bool = False):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.key_env = key_env
        self.rpm = rpm
        self.confirm = confirm
        self.requests = 0
        self._min_interval = 60.0 / max(rpm, 1)
        self._last = 0.0

    def _headers(self):
        import urllib.request
        key = os.environ.get(self.key_env)
        if not key:
            raise RuntimeError(f"missing API key: set {self.key_env}")
        return {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}

    def generate(self, prompt: str) -> str:
        if not self.confirm:
            raise RuntimeError("APIBackend is unconfirmed. Re-create with confirm=True "
                               "after reviewing the run plan; never auto-fire at providers.")
        import json
        import urllib.request
        self._throttle()
        body = json.dumps({"model": self.model, "messages": [{"role": "user",
                           "content": prompt}]}).encode("utf-8")
        req = urllib.request.Request(self.base_url + "/chat/completions",
                                     data=body, headers=self._headers())
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        self.requests += 1
        return data["choices"][0]["message"]["content"]

    def execute(self, payload: dict, lane: str = "model_guardrail") -> dict:
        prompt = payload.get("full_prompt") or payload.get("prompt", "")
        text = self.generate(prompt)
        return {"response": text, "error": ""}

    def _throttle(self):
        now = time.time()
        wait = self._last + self._min_interval - now
        if wait > 0:
            time.sleep(wait)
        self._last = time.time()


class CLIBackend:
    """Executes payloads through a local command-line agent on your machine
    (agentic CLIs such as Claude Code or Codex, or any scriptable tool).

    command: a list of argv elements (preferred, quoting-safe on Windows) or
    a shell-style string. Placeholders: {prompt} is replaced by the payload
    text as ONE argv element, so no shell quoting is needed; {prompt_file} is
    replaced by the path of a temp file containing the payload (useful for
    file-ingestion tests).

    Example command lists:
      ["claude", "-p", "{prompt}"]
      ["codex", "exec", "{prompt}"]
      ["python", "tool.py", "--input", "{prompt_file}"]
    """

    def __init__(self, command, timeout_s: int = 180, cwd: str = None,
                 confirm: bool = True):
        import shlex
        if isinstance(command, str):
            self.command = shlex.split(command, posix=(os.name != "nt"))
        else:
            self.command = list(command)
        self.timeout_s = timeout_s
        self.cwd = cwd
        self.confirm = confirm
        self.requests = 0

    def _argv(self, prompt: str) -> list:
        import tempfile
        if "{prompt_file}" in self.command:
            fd, path = tempfile.mkstemp(suffix=".txt", prefix="autort_prompt_")
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(prompt)
            return [path if part == "{prompt_file}" else part for part in self.command]
        return [prompt if part == "{prompt}" else part for part in self.command]

    def execute(self, payload: dict, lane: str = "model_guardrail") -> dict:
        import subprocess
        if not self.confirm:
            return {"response": "", "error": "CONFIRM_REQUIRED"}
        prompt = payload.get("full_prompt") or payload.get("prompt", "")
        self.requests += 1
        try:
            proc = subprocess.run(self._argv(prompt), capture_output=True, text=True,
                                  timeout=self.timeout_s, cwd=self.cwd)
        except subprocess.TimeoutExpired:
            return {"response": "", "error": "TIMEOUT"}
        except FileNotFoundError as e:
            return {"response": "", "error": f"NOT_FOUND: {e}"}
        text = (proc.stdout or "") + (("\n" + proc.stderr) if proc.stderr else "")
        return {"response": text, "error": "" if proc.returncode == 0 else f"EXIT_{proc.returncode}"}

    def generate(self, prompt: str) -> str:
        return self.execute({"prompt": prompt}).get("response", "")


class BrowserBackend:
    """App-lane backend: executes canary payloads through the webrunner
    driver against a declared in-scope app target. Responses are the
    captured assistant text; classification happens via marker obedience."""

    def __init__(self, target: dict, out_dir: str = "results/bounty/webshots",
                 headless: bool = True):
        self.target = target
        self.out_dir = out_dir
        self.headless = headless
        self.requests = 0

    def execute(self, payload: dict, lane: str = "app_violations") -> dict:
        from webrunner.driver import run_target
        self.requests += 1
        text = payload.get("full_prompt") or payload.get("prompt", "")
        marker = payload.get("marker", "")
        r = run_target(self.target, text, out_dir=self.out_dir,
                       headless=self.headless, marker=marker)
        return {"response": r.get("transcript", ""), "error": "",
                "screenshot": r.get("screenshot", "")}
