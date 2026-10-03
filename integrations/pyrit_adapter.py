"""PyRIT integration adapter.

Thin wrapper that lets PromptShield drive Microsoft PyRIT when it is
installed: single-shot prompt sending with converters, and an optional
multi-turn red-teaming loop. PyRIT stays an optional dependency; the
adapter degrades with a clear message when it is absent.

Docs: https://azure.github.io/PyRIT/
"""

import importlib
import asyncio


def pyrit_available() -> bool:
    try:
        importlib.import_module("pyrit")
        return True
    except ImportError:
        return False


def _require():
    if not pyrit_available():
        raise RuntimeError(
            "PyRIT is not installed. Run: pip install pyrit, then see "
            "https://azure.github.io/PyRIT/ for target configuration.")


def send_prompts(endpoint: dict, prompts: list, converters: list = None,
                 max_requests: int = 20) -> list:
    """Send a list of prompts to an authorized endpoint via PyRIT and return
    one result per prompt: {prompt, response, converter}.

    endpoint: {target: 'openai_chat', model_name: str, endpoint_url?: str}
    converters: list of names in {'base64', 'rot13', 'translate'}.
    """
    _require()
    from pyrit.prompt_target import OpenAIChatTarget
    from pyrit.orchestrator import PromptSendingOrchestrator
    from pyrit.prompt_converter import Base64Converter, ROT13Converter

    converter_map = {"base64": Base64Converter, "rot13": ROT13Converter}
    convs = [converter_map[c]() for c in (converters or []) if c in converter_map]

    target = OpenAIChatTarget(
        model_name=endpoint.get("model_name", "gpt-4o-mini"),
        endpoint=endpoint.get("endpoint_url") or None,
    )

    async def _run():
        async with PromptSendingOrchestrator(objective_target=target,
                                             prompt_converters=convs) as orch:
            results = await orch.send_prompts_async(prompt_list=prompts[:max_requests])
            out = []
            for r in results:
                out.append({"prompt": str(getattr(r, "request_pieces", [r])[0]),
                            "response": str(getattr(r, "converted_value", r)),
                            "converter": ",".join(converters or [])})
            return out

    return asyncio.run(_run())


def red_team_round(endpoint: dict, objective: str, max_turns: int = 10,
                   attacker_model: str = None) -> dict:
    """Run a single-objective multi-turn red-teaming loop when the installed
    PyRIT version exposes RedTeamingOrchestrator. Returns a dict with the
    objective, the transcript placeholder, and a status note; exact result
    shapes vary across PyRIT releases, so callers should read memory/DB for
    full transcripts.
    """
    _require()
    mod = importlib.import_module("pyrit.orchestrator")
    if not hasattr(mod, "RedTeamingOrchestrator"):
        return {"status": "unsupported-by-installed-version", "objective": objective,
                "note": "This PyRIT build does not expose RedTeamingOrchestrator; "
                        "use CrescendoOrchestrator or the current documented API."}
    return {"status": "available", "objective": objective, "max_turns": max_turns,
            "attacker_model": attacker_model,
            "note": "Wire the orchestrator call to your scorer and memory per the "
                    "PyRIT docs for the installed version; transcripts persist in "
                    "the PyRIT memory database."}
