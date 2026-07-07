---
name: browser-harness
description: Drive an existing browser through CDP for authenticated, visual, or interactive web automation. 
category: Document Processing
source: antigravity
tags: [python, node, pdf, api, claude, ai, agent, automation, workflow, design]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/browser-harness
---


# browser-harness

## When to Use

- Use when a task needs a real logged-in browser, visible interaction, or JS-heavy page control.
- Use when static fetches are insufficient and CDP browser automation is appropriate.

Direct browser control via CDP. For task-specific edits, use `agent-workspace/agent_helpers.py`. For setup, install, or connection problems, read install.md.

**Routing check first:** if the task needs no interaction (no clicks, logins, or forms) and you just want page content, use DeepAPI `POST /v1/scrape/website` instead of driving a browser — see the `deepapi` skill. Use browser-harness when the task needs a real browser: interaction, JS-heavy flows, logged-in sessions, or visual verification.

Domain skills (community-contributed per-site playbooks under `agent-workspace/domain-skills/`) are off by default. Set `BH_DOMAIN_SKILLS=1` to enable them; see the bottom section.

**If `BH_DOMAIN_SKILLS=1` and the task is site-specific, read every file in the matching `agent-workspace/domain-skills/<site>/` directory before inventing an approach.**

## Usage

```bash
browser-harness -c '
new_tab("https://docs.browser-use.com")
wait_for_load()
print(page_info())
'
```

- Invoke as browser-harness — it's on $PATH. No cd, no uv run.
- First navigation is new_tab(url), not goto_url(url) — goto runs in the user's active tab and clobbers their work.

## Tool call shape

```bash
browser-harness -c '
# any python. helpers pre-imported. daemon auto-starts.
'
```

run.py calls ensure_daemon() before exec — you never start/stop manually unless you want to.

### Remote browsers

Use remote for parallel sub-agents (each gets its own isolated browser via a distinct BU_NAME) or on a headless server. BROWSER_USE_API_KEY must be set. start_remote_daemon, list_cloud_profiles, list_local_profiles, sync_local_profile are pre-imported.

When supervising those sub-agents, after each check send the user one very short status line: what they are doing and whether they are on track.

Claude Code cmux note: after Claude finishes, it may prefill a predicted next user message; that draft is Claude, not the user speaking.

```bash
browser-harness -c '
start_remote_daemon("work")                               # default — clean browser, no profile
# start_remote_daemon("work", profileName="my-work")      # reuse a cloud profile (already logged in)
# start_remote_daemon("work", profileId="<uuid>")         # same, but by UUID
# start_remote_daemon("work", proxyCountryCode="de", timeout=120)   # DE proxy, 2-hour timeout
# start_remote_daemon("work", proxyCountryCode=None)      # disable the Browser Use proxy
'

BU_NAME=work browser-harness -c '
new_tab("https://example.com")
print(page_info())
'
```

start_remote_daemon prints liveUrl and auto-opens it in the local browser (if a GUI is detected) so the user can watch along. Headless servers print only — share the URL with the user. The daemon PATCHes the cloud browser to stop on shutdown, which persists profile state. Running remote daemons bill until timeout.

Profiles (cookies-only login state) live in interaction-skills/profile-sync.md — covers list_cloud_profiles(), the chat-driven "which profile?" pattern, and sync_local_profile() for uploading a local Chrome profile.

## Interaction skills

If you start struggling with a specific mechanic while navigating, look in interaction-skills/ for helpers. They cover reusable UI mechanics like dialogs, tabs, dropdowns, iframes, and uploads. The available interaction skills are:
- connection.md
- cookies.md
- cross-origin-iframes.md
- dialogs.md
- downloads.md
- drag-and-drop.md
- dropdowns.md
- iframes.md
- network-requests.md
- print-as-pdf.md
- profile-sync.md
- screenshots.md
- scrolling.md
- shadow-dom.md
- tabs.md
- uploads.md
- viewport.md

## What actually works

- Screenshots first: use capture_screenshot() to understand the current page quickly, find visible targets, and decide whether you need a click, a selector, or more navigation.
- Clicking: capture_screenshot() → read the pixel off the image → click_at_xy(x, y) → capture_screenshot() to verify. Suppress the Playwright-habit reflex of "locate first, then click" — no getBoundingClientRect, no selector hunt. Drop to DOM only when the target has no visible geometry (hidden input, 0×0 node). Hit-testing happens in Chrome's browser process, so clicks go through iframes / shadow DOM / cross-origin without extra work.
- Bulk HTTP: http_get(url) + ThreadPoolExecutor. No browser for static pages (249 Netflix pages in 2.8s).
- After goto: wait_for_load().
- Wrong/stale tab: ensure_real_tab(). Use it when the current tab is stale or internal; the daemon also auto-recovers from stale sessions on the next call.
- Verification: print(page_info()) is the simplest "is this alive?" check, but screenshots are the default way to verify whether a visible action actually worked.
- DOM reads: use js(...) for inspection and extraction when the screenshot shows that coordinates are the wrong t
