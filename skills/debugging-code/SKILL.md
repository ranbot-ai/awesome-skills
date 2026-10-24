---
name: debugging-code
description: Interactively debug source code — set breakpoints, step through execution line by line, inspect live variable state, evaluate expressions against the running program, and navigate the call stack to 
category: Development & Code Tools
source: antigravity
tags: [python, typescript, node, api, claude, ai, agent, presentation, security, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/debugging-code
---


# Interactive Debugger
## When to Use

Use this skill when you need interactively debug source code — set breakpoints, step through execution line by line, inspect live variable state, evaluate expressions against the running program, and navigate the call stack to trace root causes. Use when a program crashes, raises unexpected exceptions, produces...


Use when a program crashes, produces wrong output, or you need to understand exactly
how execution reached a particular state — and running it again with more print statements
won't give you the answer fast enough.

You can pause a running program at any point, read live variable values and the call stack
at that exact moment, step forward line by line or jump to the next breakpoint, and
evaluate arbitrary expressions against the live process — all without restarting.

## Setup

This skill uses `dap`, a CLI tool that background daemon to interact with the debugger via the DAP Protocol, maintain
the debugger state, so you can simply interact with it with multiple calls.

If `dap` isn't installed (check: `command -v dap`), check the project's approved installation method and version.
Ask/notify the user before proceeding to install it.

From Homebrew (macOS)

```bash
brew install AlmogBaku/tap/dap
```

Installer script:

```bash
DAP_VERSION=REVIEWED_TAG DAP_SHA256=TRUSTED_PLATFORM_SHA256 bash /absolute/path/to/skill/scripts/install-dap.sh
```

Install from sources:

```bash
go install github.com/AlmogBaku/debug-skill/cmd/dap@REVIEWED_TAG
```

This tool is open-sourced and available on [GitHub](https://github.com/AlmogBaku/debug-skill), an external dependency requiring version/provenance review.

Supports natively Python, Go, Node.js/TypeScript, Rust, C/C++, and any other language that supports DAP.

If a debugger backend is missing or fails to start, see `references/installing-debuggers.md`

For all commands and flags: `dap --help` or `dap <cmd> --help`.

## Execution boundaries

Launching/attaching runs or pauses real code. Confirm executable, process owner,
arguments, environment and external side effects first; reproduce on isolated
fixtures with no production credentials. Debugger ports allow code execution:
bind locally, use authenticated tunnels if needed, and never expose adapters
publicly. Variable inspection, properties and conditional breakpoints may invoke
user-defined getters/functions; avoid printing tokens, personal data or full config.
No debugger or language adapter is bundled; verify actual CLI help/version.

## Starting a Session

`dap debug <file>` launches the program under the debugger. Backend is auto-detected from the file extension.

Choose your starting strategy based on what you know:

- **Have a hypothesis** — set a breakpoint where you expect the bug: `dap debug script.py --break script.py:42`
- **Conditional breakpoint** — only stop when a condition is met: `dap debug script.py --break "script.py:42:x > 5"` (
  always quote specs with conditions)
- **Multi-file app** — breakpoints across modules: `--break src/api/routes.py:55 --break src/models/user.py:30`
- **No hypothesis, small program** — walk from entry: `dap debug script.py --stop-on-entry` (avoid for large projects —
  startup code is noisy; bisect with breakpoints instead)
- **Exception, location unknown** — `dap debug script.py --break-on-exception raised` (Python) / `all` (Go/JS)
- **Remote process** — `dap debug --attach host:port --backend <name>`
- **Process already running (stuck server, live issue)** — attach without restarting:
  `dap debug --pid <PID> --backend <name>`
  > Debugger attachment permissions vary by OS signing, process and backend.
  > Do not disable SIP or other platform protections to make attachment work;
  > use a signed development build launched under its approved debugger.

**Session isolation:** `--session <name>` keeps concurrent agents from interfering.
Tip: You might want to use your session id(${CLAUDE_SESSION_ID}) if available.

Run `dap debug --help` for all flags, backends, and examples.

## The Debugging Mindset

Reach for a debugger when reading source alone can't validate the root cause.
A debugger lets you *observe* what *does* happen: actual values, actual path, actual state.
When that diverges from what *should* happen, you've found your bug.

**Two strikes, rethink.** If two hypotheses fail at the same location, your mental model is wrong.
Re-read the code, form a *completely different* theory with different breakpoints.

**Escalate gradually.** Start with `dap eval` to test a quick hypothesis. Use conditional breakpoints
to filter noise. Fall back to full breakpoints + stepping only when you need interactive control.

**Mimic the user journey.** If you're debugging a user flow, set breakpoints along the path you expect the code to take.
If you expected `compute()` to be called, but it never is, then the bug is in the caller — not `compute()`, but whatever
was supposed to call it.

**Set breakpoints instead of prints.** When you
