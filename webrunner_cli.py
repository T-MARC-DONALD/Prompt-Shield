"""Browser runner CLI: drive AI websites with the campaign corpus.

Commands:
  calibrate --site NAME [--profile-dir DIR]
      Opens the site headed, tests every candidate selector, reports which
      resolve, and leaves you logged in inside the persistent profile.

  run --site NAME --payloads FILE [--limit N] [--campaign FILE] [--marker-hex]
      Sends each payload through the site's web UI, captures the response and
      screenshot, classifies it, and (with --campaign) records the attempt in
      the campaign file used by bounty_cli report.

  selftest
      Offline validation of cascade resolution and stability waiting.

Terms reality: run only against your own accounts, keep volumes low, and for
bug bounty submissions only test apps the program lists as in-scope.
"""

import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from webrunner.driver import run_site, calibrate_site, run_selftest, playwright_ready
from bounty.textnorm import marker_in_text


def load_yaml(path):
    import yaml
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_site(sites_path, name):
    doc = load_yaml(sites_path)
    for s in doc.get("sites", []):
        if s.get("name") == name:
            url = s.get("url", "")
            if url.startswith("file:///..."):  # resolve offline selftest placeholders
                root = os.path.dirname(os.path.abspath(__file__)).replace("\\", "/")
                s["url"] = "file:///" + root + url[len("file:///..."):]
            return s
    raise KeyError(f"site '{name}' not found in {sites_path}")


SITE_TEMPLATE = {
    "login_note": "Sign in once; the session persists in the profile.",
    "response_exclude": ["user", "human"],
    "selectors": {
        "input": ["textarea", "div[contenteditable='true']", "input[type='text']"],
        "send": ["button[type='submit']", "button[aria-label*='Send']",
                 "button[aria-label*='Submit']"],
        "response": ["[data-testid*='assistant-message']", "div[class*='markdown']",
                     "div[class*='prose']", "main"],
    },
}


def add_site(sites_path: str, name: str, url: str, login_note: str = "") -> bool:
    """Append a new site profile with generic cascades to sites.yaml.
    Returns False when the site already exists."""
    import yaml
    with open(sites_path, encoding="utf-8") as f:
        doc = yaml.safe_load(f) or {}
    sites = doc.setdefault("sites", [])
    if any(s.get("name") == name for s in sites):
        return False
    entry = {"name": name, "url": url}
    entry.update({k: (v if k != "login_note" or not login_note else login_note)
                  for k, v in SITE_TEMPLATE.items()})
    sites.append(entry)
    with open(sites_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(doc, f, sort_keys=False, allow_unicode=True)
    return True


def load_payloads(path):
    """Accept a payloads YAML, a campaign YAML (canaries are expanded into
    payloads), a single payload dict, or a list of payloads."""
    doc = load_yaml(path)
    if isinstance(doc, list):
        return doc
    if isinstance(doc, dict):
        if "payloads" in doc:
            return doc["payloads"]
        if "canaries" in doc:  # campaign file -> expand canaries into payloads
            from bounty.canary import generate_canary
            out = []
            for c in doc["canaries"]:
                marker = c.get("marker", "")
                key = f"{c.get('shape')}:{c.get('vector')}"
                content = generate_canary(c.get("shape"), c.get("vector"), marker)["content"]
                out.append({"id": key, "canary_key": key, "prompt": content,
                            "marker": marker, "shape": c.get("shape"),
                            "vector": c.get("vector"), "tier": 5,
                            "category": "app_document_injection",
                            "success_signals": [marker] if marker else []})
            return out
        return [doc]
    return []


def main(argv=None):
    ap = argparse.ArgumentParser(prog="webrunner_cli")
    ap.add_argument("--sites", default=os.path.join(os.path.dirname(
        os.path.abspath(__file__)), "webrunner", "sites.yaml"))
    sub = ap.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("calibrate")
    sp.add_argument("--site", required=True)
    sp.add_argument("--profile-dir", default="webrunner/profile")
    sp.add_argument("--out", default="results/bounty/webshots")
    sp.add_argument("--wait-ms", type=int, default=8000,
                    help="settle time before probing (raise for slow SPAs)")
    sp.add_argument("--probe", action="store_true",
                    help="type and send one probe message to reveal the send "
                         "button and response containers that appear only after interaction")
    sp.add_argument("--headless", action="store_true")

    sp = sub.add_parser("add-site")
    sp.add_argument("--name", required=True)
    sp.add_argument("--url", required=True)
    sp.add_argument("--login-note", default="")

    sp = sub.add_parser("run")
    sp.add_argument("--site", required=True)
    sp.add_argument("--payloads", required=True)
    sp.add_argument("--limit", type=int, default=3)
    sp.add_argument("--profile-dir", default="webrunner/profile")
    sp.add_argument("--out", default="results/bounty/webshots")
    sp.add_argument("--campaign", default="", help="campaign yaml to record attempts into")
    sp.add_argument("--pace", type=float, default=5.0,
                    help="seconds to wait between payloads (be gentle with live sites)")
    sp.add_argument("--repeat", type=int, default=1,
                    help="repeat each payload N times for reliability runs")
    sp.add_argument("--headless", action="store_true")

    sub.add_parser("selftest")

    args = ap.parse_args(argv)

    if args.cmd == "add-site":
        added = add_site(args.sites, args.name, args.url, args.login_note)
        print(f"{'added' if added else 'already exists'}: {args.name} -> {args.sites}")
        print("Next: python webrunner_cli.py calibrate --site " + args.name)
        return 0 if added else 1

    if not playwright_ready():
        print("Playwright not installed. Run: pip install playwright")
        return 2

    if args.cmd == "selftest":
        r = run_selftest(out_dir="results/bounty/webshots")
        print(json.dumps({"selftest_passed": r["selftest_passed"],
                          "transcript": r["transcript"][:120],
                          "screenshot": r["screenshot"]}, indent=2))
        return 0 if r["selftest_passed"] else 1

    site = load_site(args.sites, args.site)

    if args.cmd == "calibrate":
        probe = site.get("probe_text") if args.probe else None
        rep = calibrate_site(site, profile_dir=args.profile_dir, out_dir=args.out,
                             headless=args.headless, wait_ms=args.wait_ms,
                             probe_text=probe)
        print(json.dumps(rep, indent=2))
        print("\nLog in if prompted, then re-run calibrate to confirm resolution.")
        return 0

    if args.cmd == "run":
        payloads = load_payloads(args.payloads)[:args.limit]
        if args.repeat and args.repeat > 1:
            payloads = [p for p in payloads for _ in range(args.repeat)]
        os.makedirs(args.out, exist_ok=True)
        campaign = None
        if args.campaign:
            from bounty.campaign import Campaign
            campaign = Campaign.from_yaml(args.campaign)
        rows = []
        for idx, p in enumerate(payloads):
            text = p.get("full_prompt") or p.get("prompt", "")
            marker = p.get("marker", "")
            if not text:
                continue
            if idx and args.pace:
                time.sleep(args.pace)
            r = run_site(site, text, marker=marker, out_dir=args.out,
                         profile_dir=args.profile_dir, headless=args.headless)
            # keep one screenshot per payload so evidence is not overwritten
            shot = r.get("screenshot", "")
            if shot and os.path.exists(shot):
                safe = "".join(ch if ch.isalnum() or ch in "-_." else "_"
                               for ch in str(p.get("id", "payload")))
                stamp = time.strftime("%H%M%S")
                uniq = os.path.join(args.out, f"{args.site}_{safe}_{stamp}_capture.png")
                try:
                    os.replace(shot, uniq)
                    r["screenshot"] = uniq
                except OSError:
                    pass
            marker_hit = bool(marker) and marker_in_text(r.get("transcript", ""), marker)
            signals = p.get("success_signals") or []
            signal_hits = [s for s in signals
                           if marker_in_text(r.get("transcript", ""), str(s))]
            # behavior counts even when the model drops the requested token:
            # a declared success signal present in the reply is adoption.
            adopted = marker_hit or bool(signal_hits)
            row = {"payload_id": p.get("id"), "site": args.site,
                   "error": r.get("error", ""), "marker_hit": marker_hit,
                   "adopted": adopted, "signal_hits": signal_hits,
                   "transcript_head": r.get("transcript", "")[:300],
                   "screenshot": r.get("screenshot", ""),
                   "selectors_used": r.get("selectors_used", {})}
            rows.append(row)
            if campaign:
                try:
                    campaign.record_attempt(p.get("canary_key") or
                                            f"{p.get('shape', 'html_page')}:{p.get('vector', 'content_framed')}",
                                            r.get("transcript", ""),
                                            model_version=f"{args.site} (web UI)",
                                            interface="web app",
                                            screenshots=[r.get("screenshot", "")] if r.get("screenshot") else [])
                except KeyError:
                    pass
                campaign.save()
            print(json.dumps(row, indent=2))
        out = os.path.join(args.out, f"run_{args.site}_{len(rows)}payloads.json")
        with open(out, "w", encoding="utf-8") as f:
            json.dump(rows, f, indent=2)
        print("run summary:", out)
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
