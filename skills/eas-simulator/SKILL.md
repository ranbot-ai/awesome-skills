---
name: eas-simulator
description: Curated upstream guidance for Eas Simulator; use when the workflow matches the user goal. 
category: Document Processing
source: antigravity
tags: [api, ai, agent, automation, workflow, document, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/eas-simulator
---

## When to Use
- Use when this upstream workflow matches the user's stated goal.
- Use when the task requires the procedures documented in this skill.

# EAS Simulator

> **EAS service - costs apply.** EAS Simulator is a hosted EAS service. Session usage is subject to your account's pricing and limits. See https://expo.dev/pricing for current terms.

EAS Simulator runs a remote iOS simulator or Android emulator on EAS infrastructure that you drive from your machine — from the CLI, from an AI agent (via `agent-device`), and from a browser preview. It's the unlock for **environments that can't run a simulator locally** (Linux boxes, cloud/background agents like Cursor Cloud), and for letting an agent *verify* a change on a real device instead of only reasoning about code.

The `simulator:*` commands are **experimental and hidden**, and need a recent eas-cli (≥ 20.3.0 as of writing) — which is why this skill runs everything via `npx --yes eas-cli@latest`. Flags and verbs may change; **the relevant subcommand's `--help` output is authoritative.**

## When to Use
The frontmatter `description` carries the trigger phrases. In short: use this to get a user's app onto a **cloud** simulator and interact with it — especially from a Mac-less or cloud/sandbox agent. **Not** for local sims (`expo run:ios`, Xcode, Android Studio), store builds/signing (that's EAS Build), or physical devices. For the macOS case, see *Cloud vs local* next.

## Cloud vs local: decide this first

- **Explicit cloud/remote/shareable request:** use EAS Simulator after checking access, on any host.
- **Generic simulator request:** use a suitable local simulator when available. If the host cannot run the requested simulator (for example, iOS on Linux or a cloud sandbox), use EAS Simulator after checking access. A non-macOS host may still support a local Android emulator.
- Honor an explicit local choice; hand off to `expo run:ios` / Xcode / Android Studio as appropriate. Clarify only when the requested environment remains ambiguous and affects the task.

When the user requests EAS Simulator or a cloud simulator, proceed within that request and
any stated budget. Explain applicable usage once and carry existing authorization through
the session. Ask before exceeding a stated budget or expanding beyond the requested work.

## Prerequisites

- **Run every `eas` command via `npx --yes eas-cli@latest …`** — guarantees a CLI new enough to have `simulator:*` (a global `eas` is often too old), and `--yes` skips npx's prompt. (Bare `eas` is fine if `eas --version` is current.)
- **Authenticated.** Interactive machine → `npx --yes eas-cli@latest login`. **Cloud sandbox / CI / headless agent has no browser login — set `EXPO_TOKEN`** (expo.dev → Account → Access Tokens) in the env instead. Verify either way with `npx --yes eas-cli@latest whoami`.
- Run from an Expo **project directory.** A fresh app needs one-time setup: `npx --yes eas-cli@latest init` to create/link the project (when there's no `projectId`), and **set `ios.bundleIdentifier`** in app config if it's missing — a fresh `create-expo-app` often has none, and `prebuild`/`eas build` need it (they prompt or fail without it; e.g. `dev.<owner>.<slug>`). Read current config with `npx expo config --json` (it may live in `app.config.js`). The first Mode-C run is slow (native build); later runs reuse it.
- A controller to drive the device. This skill uses **agent-device** (open source, MIT), run on demand via `npx agent-device@latest` — nothing globally installed. **Appium** and **argent** are alternative automation interfaces; `web-preview-only` has no automation interface. See [references/controllers.md].
- **`.env.eas-simulator`** is written/managed by eas-cli (not this skill): it holds the session id (`EAS_SIMULATOR_SESSION_ID`) + the daemon URL/**token**, so `get`/`stop`/`exec` default to that session (usually **omit `--id`**; pass `--id <id>` to target another). It carries a **token → keep it gitignored** (eas-cli marks it "do not commit" but may not add the ignore rule, and a fresh app's `.gitignore` won't cover it — add `.env.eas-simulator` if missing).
- **The command blocks assume a POSIX shell** (bash/zsh) — `printf`, `lsof`, `$(seq …)` loops won't run in cmd/PowerShell. On Windows, run them in WSL or Git Bash, or translate as you go (the `eas-cli`/`agent-device` invocations themselves are cross-platform).

## Session lifetime

- `--max-duration-minutes N` is the hard automatic-stop deadline. Customize it when supported by the account; otherwise use the service's default session limit.
- `--max-idle-time-minutes N` stops a session after that many inactive minutes. Omitted means **no idle timeout**: the session runs until its maximum duration or an explicit stop.
- **Only activity reported through `agent-device` and `argent` resets the idle timer.** Appium commands and browser-preview activity do not reset it. For Appium or a user-driven browser preview, rely on the maximum duration—not idle tim
