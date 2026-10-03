"""Browser automation driver for AI sites and app-lane targets.

Two modes:

1. run_target(target, ...)  - generic step-list runner (backward compatible).
2. run_site(site, ...)      - drives an AI website profile: opens the site in
   a persistent, logged-in browser profile, resolves the input/send/response
   selectors from a candidate cascade, sends the payload, waits for the
   response to stabilize, captures text + screenshot, and reports which
   selectors actually worked (calibration data).

Scope discipline: run only against targets you are authorized to test, on
your own accounts. Consumer AI sites have terms of service that may restrict
automation; prefer official APIs where a program expects API evidence, and
for bug bounty submissions only test apps listed as in-scope by the program.

Requires: pip install playwright (a system Chrome/Edge is used automatically
when the bundled Chromium is not installed).
"""

import os
import time

try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_OK = True
except ImportError:
    sync_playwright = None
    PLAYWRIGHT_OK = False


def playwright_ready() -> bool:
    return PLAYWRIGHT_OK


# ---------------------------------------------------------------- helpers

def _as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def resolve_selector(page, candidates, timeout_ms: int = 8000) -> str:
    """Return the first candidate selector that matches a visible element.

    Cascade order is the site profile's declared order; the first match wins.
    Returns "" when none match.
    """
    deadline = time.time() + timeout_ms / 1000
    while time.time() < deadline:
        for sel in _as_list(candidates):
            try:
                el = page.query_selector(sel)
                if el is not None:
                    return sel
            except Exception:
                continue
        page.wait_for_timeout(250)
    return ""


def wait_for_stable(page, selector: str, quiet_ms: int = 2500,
                    timeout_ms: int = 90000) -> str:
    """Poll the element's text until it stops changing for quiet_ms."""
    last, stable_since, deadline = "", None, time.time() + timeout_ms / 1000
    while time.time() < deadline:
        try:
            el = page.query_selector(selector)
            current = (el.inner_text() if el else "") or ""
        except Exception:
            current = ""
        if current and current == last:
            if stable_since is None:
                stable_since = time.time()
            elif (time.time() - stable_since) * 1000 >= quiet_ms:
                return current
        else:
            stable_since = None
        last = current
        page.wait_for_timeout(400)
    return last


def _launch(p, profile_dir: str = None, headless: bool = True):
    """Launch a browser and return (context, browser).

    With a profile_dir, a persistent context is returned in slot 1 and the
    browser slot is None (persistent contexts own their browser). Without a
    profile_dir, a fresh context and its browser are returned.
    """
    errors = []
    if profile_dir:
        for opts in ({}, {"channel": "msedge"}, {"channel": "chrome"}):
            try:
                ctx = p.chromium.launch_persistent_context(
                    user_data_dir=profile_dir, headless=headless, **opts)
                return ctx, None
            except Exception as e:
                errors.append(str(e).splitlines()[0])
        raise RuntimeError("Could not launch a persistent browser. Errors: "
                           + " | ".join(errors))
    for opts in ({}, {"channel": "msedge"}, {"channel": "chrome"}):
        try:
            browser = p.chromium.launch(headless=headless, **opts)
            return browser.new_context(), browser
        except Exception as e:
            errors.append(str(e).splitlines()[0])
    raise RuntimeError("Could not launch Chromium, Edge, or Chrome. Errors: "
                       + " | ".join(errors))


def _new_page(ctx, browser):
    return ctx.new_page()


def _close(browser, ctx):
    try:
        ctx.close()
    finally:
        if browser is not None:
            browser.close()


def _render(value: str, payload_text: str, marker: str = "") -> str:
    return (value or "").replace("{{PAYLOAD}}", payload_text).replace("{{MARKER}}", marker)


# ---------------------------------------------------------------- mode 1

def run_target(target: dict, payload_text: str, out_dir: str = "webshots",
               headless: bool = True, marker: str = "",
               profile_dir: str = None, page_timeout_ms: int = 45000) -> dict:
    """Execute a target's step list (see webrunner/targets.yaml)."""
    if not PLAYWRIGHT_OK:
        raise RuntimeError("Playwright is not installed. Run: pip install playwright")
    name = target.get("name", "target")
    os.makedirs(out_dir, exist_ok=True)
    transcript, shot_path, final_url = "", "", ""
    with sync_playwright() as p:
        ctx, browser = _launch(p, profile_dir=profile_dir, headless=headless)
        page = ctx.new_page()
        page.set_default_timeout(page_timeout_ms)
        try:
            for step in target.get("steps", []):
                action = step.get("action")
                sel = step.get("selector")
                val = _render(step.get("value", ""), payload_text, marker)
                ms = int(step.get("ms", 300))
                if action == "goto":
                    page.goto(val or target.get("url", ""))
                    page.wait_for_load_state("domcontentloaded")
                elif action == "fill":
                    page.fill(resolve_selector(page, sel) or _as_list(sel)[0], val)
                elif action == "type":
                    page.type(resolve_selector(page, sel) or _as_list(sel)[0], val, delay=15)
                elif action == "click":
                    page.click(resolve_selector(page, sel) or _as_list(sel)[0])
                elif action == "press":
                    page.press(resolve_selector(page, sel) or _as_list(sel)[0], val or "Enter")
                elif action == "upload":
                    page.set_input_files(resolve_selector(page, sel) or _as_list(sel)[0], val)
                elif action == "wait":
                    page.wait_for_timeout(ms)
                elif action == "extract":
                    transcript += page.inner_text(sel) + "\n"
                time.sleep(ms / 1000)
            resp_sel = target.get("response_selector")
            if resp_sel:
                resolved = resolve_selector(page, resp_sel)
                if resolved:
                    transcript += wait_for_stable(page, resolved)
            final_url = page.url
            shot_path = os.path.join(out_dir, f"{name.replace(' ', '_')}_capture.png")
            page.screenshot(path=shot_path, full_page=True)
        finally:
            _close(browser, ctx)
    return {"target": name, "url": final_url, "transcript": transcript.strip(),
            "screenshot": shot_path if os.path.exists(shot_path) else "",
            "selectors_used": {}}


# ---------------------------------------------------------------- mode 2

def run_site(site: dict, payload_text: str, marker: str = "",
             out_dir: str = "results/bounty/webshots", profile_dir: str = "webrunner/profile",
             headless: bool = False, login_wait_ms: int = 0,
             stability_ms: int = 2500) -> dict:
    """Drive one AI website with one payload. Returns transcript, screenshot,
    and the selectors that resolved (calibration data)."""
    if not PLAYWRIGHT_OK:
        raise RuntimeError("Playwright is not installed. Run: pip install playwright")
    name = site.get("name", "site")
    os.makedirs(out_dir, exist_ok=True)
    selectors = site.get("selectors", {})
    result = {"site": name, "url": site.get("url", ""), "transcript": "",
              "screenshot": "", "selectors_used": {}, "error": ""}
    with sync_playwright() as p:
        ctx, browser = _launch(p, profile_dir=profile_dir, headless=headless)
        page = ctx.new_page()
        page.set_default_timeout(60000)
        try:
            page.set_default_navigation_timeout(45000)
            nav_err = None
            for attempt in range(3):
                try:
                    page.goto(site.get("url", ""), wait_until="domcontentloaded", timeout=45000)
                    nav_err = None
                    break
                except Exception as e:
                    nav_err = e
                    page.wait_for_timeout(2500 * (attempt + 1))
            if nav_err is not None:
                result["error"] = f"NAVIGATION_FAILED: {nav_err}"
                return result
            if login_wait_ms:
                page.wait_for_timeout(login_wait_ms)
            input_sel = resolve_selector(page, selectors.get("input"))
            result["selectors_used"]["input"] = input_sel
            if not input_sel:
                result["error"] = "input selector did not resolve (run calibrate)"
                return result
            page.fill(input_sel, payload_text)
            send_sel = resolve_selector(page, selectors.get("send"), timeout_ms=4000)
            if send_sel:
                page.click(send_sel)
                result["selectors_used"]["send"] = send_sel
            else:
                page.press(input_sel, "Enter")
                result["selectors_used"]["send"] = "(Enter key)"
            resp_sel = resolve_selector(page, selectors.get("response"), timeout_ms=20000)
            result["selectors_used"]["response"] = resp_sel
            if resp_sel:
                text, sel_used = capture_assistant_text(
                    page, selectors.get("response"),
                    exclude_tokens=site.get("response_exclude"),
                    quiet_ms=stability_ms)
                result["transcript"] = text
                if sel_used:
                    result["selectors_used"]["response"] = sel_used
            shot = os.path.join(out_dir, f"{name}_capture.png")
            page.screenshot(path=shot, full_page=True)
            result["screenshot"] = shot if os.path.exists(shot) else ""
            result["url"] = page.url
        finally:
            _close(browser, ctx)
    return result


def capture_assistant_text(page, candidates, exclude_tokens=None, quiet_ms: int = 2500,
                           timeout_ms: int = 90000) -> tuple:
    """Capture the LAST message matching the candidate cascade that is not an
    excluded (user-side) element. Returns (text, selector_used).

    Chat UIs render the user's own bubble with the same attributes as the
    assistant's, so capturing naively would echo the payload back and score a
    false obedience. Excluding elements whose id/class contains a token such
    as 'user' and preferring the last match avoids that.
    """
    exclude = [t.lower() for t in (exclude_tokens or ["user", "human"])]
    last_text, stable_since, used = "", None, ""
    deadline = time.time() + timeout_ms / 1000
    while time.time() < deadline:
        text, sel_used = "", ""
        for sel in _as_list(candidates):
            try:
                els = page.query_selector_all(sel)
            except Exception:
                els = []
            for el in reversed(els):
                d = _describe(el)
                if not d or not d.get("visible"):
                    continue
                ident = (str(d.get("id", "")) + " " + str(d.get("class", "")) + " "
                         + str(d.get("aria_label", ""))).lower()
                if any(tok in ident for tok in exclude):
                    continue
                try:
                    text = el.inner_text() or ""
                except Exception:
                    text = ""
                sel_used = sel
                break
            if text:
                break
        if text and text == last_text:
            if stable_since is None:
                stable_since = time.time()
            elif (time.time() - stable_since) * 1000 >= quiet_ms:
                return text, sel_used
        else:
            stable_since = None
        last_text = text
        used = used or sel_used
        page.wait_for_timeout(400)
    return last_text, used


def _describe(el) -> dict:
    try:
        return {
            "tag": el.evaluate("e => e.tagName.toLowerCase()"),
            "id": el.get_attribute("id") or "",
            "name": el.get_attribute("name") or "",
            "placeholder": el.get_attribute("placeholder") or "",
            "aria_label": el.get_attribute("aria-label") or "",
            "role": el.get_attribute("role") or "",
            "testid": el.get_attribute("data-testid") or "",
            "class": (el.get_attribute("class") or "")[:80],
            "visible": el.is_visible(),
        }
    except Exception:
        return {}


def _suggest_selector(el) -> str:
    try:
        for attr, fmt in (("data-testid", "[data-testid='{}']"), ("id", "#{}"),
                          ("aria-label", "[aria-label='{}']"),
                          ("placeholder", "[placeholder*='{}']"), ("name", "[name='{}']")):
            val = el.get_attribute(attr)
            if val:
                return fmt.format(val[:40])
    except Exception:
        pass
    return ""


def _text_blocks(page, min_chars: int = 40, cap: int = 25) -> list:
    """Visible leaf-ish text blocks: elements whose own text is substantial and
    that contain no child element with substantial text. This is how the
    assistant's message container gets discovered when its class names give
    nothing away."""
    script = """
    () => {
      const out = [];
      const walk = (el) => {
        const t = (el.innerText || '').trim();
        if (t.length < 40) return;
        let hasBigChild = false;
        for (const c of el.children) {
          const ct = (c.innerText || '').trim();
          if (ct.length >= 40) { hasBigChild = true; break; }
        }
        if (!hasBigChild) {
          out.push({
            tag: el.tagName.toLowerCase(),
            id: el.id || '',
            testid: el.getAttribute('data-testid') || '',
            role: el.getAttribute('role') || '',
            cls: (el.getAttribute('class') || '').slice(0, 90),
            chars: t.length,
            head: t.slice(0, 90)
          });
        }
        for (const c of el.children) walk(c);
      };
      walk(document.body);
      return out.slice(0, 60);
    }
    """
    try:
        return page.evaluate(script)[:cap]
    except Exception:
        return []


def _inventory(page) -> dict:
    """Dump the interactive elements on the page so selectors can be built
    from observed markup instead of guesses."""
    try:
        body_text = (page.inner_text("body") or "")[:4000].lower()
    except Exception:
        body_text = ""
    inv = {
        "url": page.url,
        "title": page.title(),
        "login_hint": any(h in body_text for h in
                          ("sign in", "sign-in", "log in", "login", "switch account")),
        "textareas": [], "inputs": [], "contenteditables": [], "buttons": [],
        "iframe_count": len(page.frames) - 1,
    }
    for sel, bucket, cap in (("textarea", "textareas", 15),
                             ("input", "inputs", 15),
                             ("div[contenteditable='true'], [contenteditable='true']", "contenteditables", 15),
                             ("button, [role='button']", "buttons", 20)):
        try:
            els = page.query_selector_all(sel)[:cap]
        except Exception:
            els = []
        for el in els:
            d = _describe(el)
            if d:
                d["suggested_selector"] = _suggest_selector(el)
                inv[bucket].append(d)
    return inv


def _response_candidates(page, cap: int = 10) -> list:
    """Visible containers that look like assistant messages."""
    out = []
    sel = ("div[class*='markdown'], div[class*='prose'], div[role='article'], "
           "div[class*='message'], [data-testid*='message'], [data-testid*='response']")
    try:
        for el in page.query_selector_all(sel)[:cap]:
            d = _describe(el)
            if d and d.get("visible"):
                d["suggested_selector"] = _suggest_selector(el) or \
                    f"{d['tag']}[class*='{d['class'].split()[0] if d['class'] else ''}']"
                out.append(d)
    except Exception:
        pass
    return out


def calibrate_site(site: dict, profile_dir: str = "webrunner/profile",
                   out_dir: str = "results/bounty/webshots",
                   headless: bool = False, wait_ms: int = 8000,
                   probe_text: str = None) -> dict:
    """Open the site, probe the candidate selectors, and optionally exercise
    the chat once (probe) to capture the send button and response containers
    that only appear after interaction."""
    if not PLAYWRIGHT_OK:
        raise RuntimeError("Playwright is not installed. Run: pip install playwright")
    selectors = site.get("selectors", {})
    report = {"site": site.get("name"),
              "resolved": {}, "candidates": {},
              "note": "Log in inside the opened window if the site asks, then re-run."}
    with sync_playwright() as p:
        ctx, browser = _launch(p, profile_dir=profile_dir, headless=headless)
        page = ctx.new_page()
        try:
            page.goto(site.get("url", ""))
            page.wait_for_load_state("domcontentloaded")
            page.wait_for_timeout(wait_ms)
            for field, candidates in selectors.items():
                checked = {}
                for sel in _as_list(candidates):
                    try:
                        checked[sel] = page.query_selector(sel) is not None
                    except Exception:
                        checked[sel] = False
                report["candidates"][field] = checked
                first = next((s for s, ok in checked.items() if ok), "")
                report["resolved"][field] = first
            inv = _inventory(page)
            report["inventory"] = {
                "url": inv["url"], "title": inv["title"],
                "login_hint": inv["login_hint"], "iframe_count": inv["iframe_count"],
                "textareas": inv["textareas"][:6],
                "contenteditables": inv["contenteditables"][:6],
                "buttons": inv["buttons"][:10],
            }
            if not report["resolved"].get("input"):
                for bucket in ("textareas", "contenteditables", "inputs"):
                    pick = next((e for e in inv[bucket] if e.get("visible")), None)
                    if pick:
                        report["auto_discovery"] = {
                            "input_from": bucket,
                            "suggested_selector": pick.get("suggested_selector", ""),
                            "element": pick,
                        }
                        break
            if not report["resolved"].get("send"):
                pick = next((b for b in inv["buttons"] if b.get("visible")), None)
                if pick:
                    report.setdefault("auto_discovery", {})["send_candidate"] = pick

            # --- interactive probe: exercise the chat once ---
            if probe_text and report["resolved"].get("input"):
                input_sel = report["resolved"]["input"]
                page.fill(input_sel, probe_text)
                page.wait_for_timeout(1000)
                inv2 = _inventory(page)
                report["post_type_buttons"] = [b for b in inv2["buttons"] if b.get("visible")][:10]
                send_sel = resolve_selector(page, selectors.get("send"), timeout_ms=4000)
                if send_sel:
                    page.click(send_sel)
                    report["send_used"] = send_sel
                else:
                    page.press(input_sel, "Enter")
                    report["send_used"] = "(Enter key)"
                page.wait_for_timeout(7000)
                report["post_send_buttons"] = [b for b in _inventory(page)["buttons"]
                                               if b.get("visible")][:10]
                report["response_candidates"] = _response_candidates(page)
                report["text_blocks_after_send"] = _text_blocks(page)
                page.screenshot(path=os.path.join(out_dir,
                                f"calibrate_{report['site']}_after_probe.png"), full_page=True)
            page.screenshot(path=os.path.join(out_dir, f"calibrate_{report['site']}.png"),
                            full_page=True)
        finally:
            _close(browser, ctx)
    return report


# ---------------------------------------------------------------- selftest

def run_selftest(out_dir: str = "results/bounty/webshots") -> dict:
    """Validate cascade resolution and stability waiting against a local page."""
    html = os.path.join(os.path.dirname(os.path.abspath(__file__)), "selftest", "echo.html")
    url = "file:///" + html.replace("\\", "/")
    target = {
        "name": "selftest echo",
        "url": url,
        "steps": [
            {"action": "goto", "value": url},
            {"action": "fill", "selector": ["#does-not-exist", "#prompt"], "value": "{{PAYLOAD}}"},
            {"action": "click", "selector": ["#nope", "#send"]},
            {"action": "wait", "ms": 300},
        ],
        "response_selector": ["#missing", "#response"],
    }
    payload = "CANARY-SELFTEST probe text"
    result = run_target(target, payload, out_dir=out_dir, headless=True)
    result["selftest_passed"] = (f"ECHO: {payload}" in result["transcript"]
                                 and "CANARY-SELFTEST" in result["transcript"])
    return result
