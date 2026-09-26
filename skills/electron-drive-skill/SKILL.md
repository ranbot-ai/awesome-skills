---
name: electron-drive-skill
description: Launch the project's Electron app on a scratch profile and drive it: click, type, screenshot, run renderer or main-process code, read logs. Use to verify UI changes end to end. 
category: Document Processing
source: antigravity
tags: [javascript, node, api, claude, ai, agent, automation, template, design, document]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/electron-drive-skill
---


# Driving the Electron app

## Overview

`scripts/drive.mjs` launches the project's Electron app under Playwright in a
background daemon and keeps it running between commands, so each action
(click, type, snapshot, screenshot, eval) is one fast shell call. Every launch
uses a scratch profile, so the agent can check a UI change or reproduce a bug
in the real app, not only in unit tests, without touching the user's data.

## When to Use This Skill

- Use when you need to verify a UI change in the running Electron app.
- Use when reproducing a renderer or startup bug, or a failure that only
  shows up in the production build (for example a stricter CSP).
- Use when checking first-run, onboarding or settings screens.
- Use when exercising a feature end to end, including IPC through the preload
  bridge or code in the main process.
- Do not use it for web apps without Electron, or for multi-window flows (see
  Limitations).

## How It Works

### Step 1: Check prerequisites

`scripts/drive.mjs`, in this skill's directory, finds the project by the
nearest `package.json`, so run it from anywhere inside the project. Set `DR`
to its absolute path.

It needs `electron` and `playwright-core` (1.49 or later) installed in the
project. If `start` says either is missing, tell the user rather than
installing it yourself. Launch settings come from `drive.config.json` at the
project root (see Step 4); with no file, it runs `electron .`.

### Step 2: Start, look, act, stop

```bash
DR=<this skill's directory>/scripts/drive.mjs

$DR start                  # last build, profile 'default'; prints status
$DR snapshot               # accessibility tree: find what to click, by role and name
$DR click 'role=button[name="Get started"]'
$DR fill 'role=textbox[name="Email"]' 'test@example.com'
$DR wait 'text=Welcome'
$DR screenshot             # prints a PNG path; Read it to see the window
$DR logs --lines 80        # main and renderer console, plus the config's logFile
$DR stop                   # ALWAYS, before finishing
```

- **Start options:**
  - `--build`: run the config's `build` command first. **Needed after any
    source change** if the app runs from a build, because the build is
    otherwise stale; `start` prints its age.
  - `--fresh`: wipe the scratch profile, which gives you the app's first-run
    state.
  - `--profile <name>`: a separate scratch profile.
  - `--dev`: see Step 5.
- **Targets** are Playwright selectors. Prefer `role=button[name="…"]` from
  `snapshot` output, then `text=…`, then CSS.
- **`--`** ends the flags. Put it before text that starts with dashes:
  `$DR fill 'role=textbox[name="Args"]' -- --verbose`.
- Other commands: `select <target> <value|label>`, `press <key>`,
  `status`, `screenshot --selector <css>`. `$DR help` lists everything.

### Step 3: Run code in the app

**`eval <js>`** runs in the renderer, **`main <js>`** in the main process
(`electron` and `process` are in scope, `require` is not). Use a bare
expression, or a body with `return`. `-` reads the code from stdin, which
avoids quoting entirely. The result comes back as JSON, so return plain data:
a DOM node or a function comes back as `undefined` or `{}`.

To exercise IPC, call whatever the app's preload exposes through `eval`. That
goes through the real preload bridge, as the app's own renderer code does.

### Step 4: Configure the launch (optional)

`drive.config.json` at the project root; every field is optional:

```json
{
  "build": "npm run build",
  "args": ["."],
  "env": { "APP_DATA_DIR": "{profile}/data" },
  "logFile": "logs/main.log",
  "dev": {
    "args": ["."],
    "env": { "ELECTRON_RENDERER_URL": "http://localhost:5173" },
    "url": "http://localhost:5173"
  }
}
```

- `args`: what Electron is launched with: an app directory whose
  `package.json` `main` is the built entry point, or the entry file itself.
- `env`: added to the app's environment. `{profile}` becomes the scratch
  profile directory (in `env` values only, not in `args`). This is how data
  kept outside `userData` is redirected: `APP_DATA_DIR` is only an example
  name, and it has an effect only if the app reads it. Check the app's source
  for the variable it actually uses.
- `logFile`: a log file relative to the profile directory, shown by `logs`.

If a project has no config and `start` fails or launches the wrong thing,
work out these values from the project's `package.json` and build setup,
then suggest a `drive.config.json` to the user.

### Step 5: Dev mode (optional)

For a fast loop on renderer code, with hot reload and source maps:

1. The user (or a background Bash call) starts the renderer dev server
   **without** its own Electron. Many templates' `start`/`dev` scripts launch
   Electron too, and two instances would share state. The config's
   `dev.url` is checked before launch.
2. `$DR start --dev` launches Electron with `dev.args` and `dev.env`, and
   `NODE_ENV=development`.

## Examples

### Example 1: Verify a change to the first-run s
