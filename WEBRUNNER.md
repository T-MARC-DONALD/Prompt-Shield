# WebRunner: browser automation for AI sites and in-app targets

Drives real AI websites (Perplexity, Gemini, DeepSeek, ChatGPT) and in-app
targets through your own logged-in browser session, sends payloads, captures
responses and screenshots, and feeds the campaign/report pipeline.

## One-time setup per site

```bash
python webrunner_cli.py calibrate --site perplexity
```

This opens the site headed, leaves you logged in inside the persistent
profile (`webrunner/profile`), tests every candidate selector, and prints
which ones resolved. If a field reports "" (nothing resolved), open the page,
inspect the element, and add the real selector at the top of that field's
cascade in `webrunner/sites.yaml`.

## Running payloads through a site

```bash
# three payloads through Perplexity, recording into the comet campaign
python webrunner_cli.py run --site perplexity \
  --payloads results/bounty/comet/comet-reef.yaml \
  --limit 3 --campaign results/bounty/comet/comet-reef.yaml

# generate the submission report from the recorded attempts
python bounty_cli.py campaign report --campaign results/bounty/comet/comet-reef.yaml \
  --out results/bounty/comet/submission_report.md
```

Each run writes a summary JSON next to the screenshots, with per-payload
marker hits, the selectors that worked, and response heads.

## Adding another app

Three paths, pick by app type:

| App type | Path | Command |
|---|---|---|
| Web app / chatbot | site profile + browser runner | `python webrunner_cli.py add-site --name myapp --url https://...` then `calibrate` then `run` |
| Agentic CLI (Claude Code, Codex) | CLI backend | `python autort_cli.py run ... --backend cli --cli-target claude-code --yes` |
| Desktop GUI (Cursor, Antigravity, Kiro, Devin) | assisted mode | perform the interaction yourself, then `python bounty_cli.py campaign record ...` |

Scaffold a new web app:

```bash
python webrunner_cli.py add-site --name myapp --url https://myapp.example/chat
python webrunner_cli.py calibrate --site myapp
python webrunner_cli.py run --site myapp --payloads payloads/tier5_appinjection.yaml --limit 3
```

CLI agent targets live in `webrunner/cli_targets.yaml`; add an entry with an
argv list, then run it through AutoRT with the cli backend. Desktop GUIs are
not browser-drivable; the assisted mode is the honest path, and the campaign
record command classifies and stores exactly as the automated paths do.

## How it is built to survive UI changes

- Selector cascades: each field lists several candidates; the first that
  resolves wins, so a site redesign usually breaks only one candidate.
- Stability waiting: the response is polled until its text stops changing,
  instead of a fixed sleep.
- Persistent profile: login once, reuse forever; headless only when you say so.
- Calibration: one command tells you exactly which candidates resolved.

## Terms and scope reality

- Use your own accounts, keep volumes low, and expect some sites to restrict
  automated interaction in their terms of service; prefer official APIs where
  a program expects API evidence.
- For bug bounty submissions, only test apps the program lists as in-scope
  (for 0din: Kiro, Claude Code, Claude Design, Cursor, Gemini Workspace [N/A],
  Antigravity, Atlas, Codex, Comet Browser, Computer, Devin Desktop).

## Offline validation

```bash
python webrunner_cli.py selftest
```

Runs cascade resolution and response capture against a local echo page using
the browser already installed on the machine. No network, no third-party site.
