"""Tests for the browser runner: selector cascades, stability waiting, and
the site-run flow against the local echo page (offline)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from webrunner.driver import (resolve_selector, wait_for_stable, run_target,
                              run_site, capture_assistant_text, playwright_ready)

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
ECHO = "file:///" + os.path.join(ROOT, "webrunner", "selftest", "echo.html").replace("\\", "/")


@unittest.skipUnless(playwright_ready(), "playwright not installed")
class TestCascade(unittest.TestCase):

    def test_cascade_picks_second_candidate(self):
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = None
            for opts in ({}, {"channel": "msedge"}, {"channel": "chrome"}):
                try:
                    browser = p.chromium.launch(headless=True, **opts)
                    break
                except Exception:
                    continue
            self.assertIsNotNone(browser, "no browser available")
            page = browser.new_page()
            try:
                page.goto(ECHO)
                resolved = resolve_selector(page, ["#does-not-exist", "#prompt"],
                                            timeout_ms=4000)
                self.assertEqual(resolved, "#prompt")
                resolved_send = resolve_selector(page, ["#nope", "#send"], timeout_ms=4000)
                self.assertEqual(resolved_send, "#send")
            finally:
                browser.close()

    def test_selftest_run_target_with_cascades(self):
        r = run_target({
            "name": "selftest cascade",
            "url": ECHO,
            "steps": [
                {"action": "goto", "value": ECHO},
                {"action": "fill", "selector": ["#nope", "#prompt"], "value": "{{PAYLOAD}}"},
                {"action": "click", "selector": ["#missing", "#send"]},
                {"action": "wait", "ms": 400},
            ],
            "response_selector": ["#absent", "#response"],
        }, "CANARY-CASCADE", out_dir="results/bounty/webshots", headless=True)
        self.assertIn("ECHO: CANARY-CASCADE", r["transcript"])

    def test_stability_wait_returns_settled_text(self):
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = None
            for opts in ({}, {"channel": "msedge"}, {"channel": "chrome"}):
                try:
                    browser = p.chromium.launch(headless=True, **opts)
                    break
                except Exception:
                    continue
            page = browser.new_page()
            try:
                page.goto(ECHO)
                page.fill("#prompt", "STABILITY-CHECK")
                page.click("#send")
                text = wait_for_stable(page, "#response", quiet_ms=500, timeout_ms=8000)
                self.assertIn("ECHO: STABILITY-CHECK", text)
            finally:
                browser.close()


    def test_assistant_capture_excludes_user_message(self):
        chat = "file:///" + os.path.join(ROOT, "webrunner", "selftest",
                                        "chat_echo.html").replace("\\", "/")
        site = {"name": "selftest chat", "url": chat,
                "response_exclude": ["user", "human"],
                "selectors": {"input": ["#prompt"], "send": ["#send"],
                              "response": ["[data-testid*='message']",
                                           "div[role='article']"]}}
        r = run_site(site, "CANARY-CHAT-PROBE", out_dir="results/bounty/webshots",
                     profile_dir=None, headless=True)
        self.assertIn("ECHO: CANARY-CHAT-PROBE", r["transcript"])
        self.assertNotIn("USER SAID:", r["transcript"])


if __name__ == "__main__":
    unittest.main()
