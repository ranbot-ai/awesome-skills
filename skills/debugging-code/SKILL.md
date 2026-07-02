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

If `dap` isn't installed (check: `command -v dap`), install it NOW.
Ask/notify the user before proceeding to install it.

From Homebrew (macOS)

```bash
brew install AlmogBaku/tap/dap
```

Installer script:

```bash
bash scripts/install-dap.sh
```

Install from sources:

```bash
go install github.com/AlmogBaku/debug-skill/cmd/dap@latest
```

This tool is open-sourced and available on [GitHub](https://github.com/AlmogBaku/debug-skill), maintained and follows
best practices.

Supports natively Python, Go, Node.js/TypeScript, Rust, C/C++, and any other language that supports DAP.

If a debugger backend is missing or fails to start, see `references/installing-debuggers.md`

For all commands and flags: `dap --help` or `dap <cmd> --help`.

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
  > **macOS + Go gotcha:** `dlv --pid` requires SIP disabled (`csrutil disable`).
  > Prefer starting the program under the debugger instead or attaching to a remote debugger!

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

**Set breakpoints instead of prints.** When you feel the urge to print something, set a breakpoint instead.

## Know Your State

Every `dap` execution command returns full context automatically: current location, source, locals, call stack, and
output. At each stop, ask:

- Do the local variables have the values I expected?
- Is the call stack showing the code path I expected?
- Does the output so far reveal anything unexpected?

**Trace causation up the stack.** If a value is wrong at frame 0, check `dap eval "<expr>" --frame 1` to see what the
caller passed. Keep going up (`--frame 2`, `--frame 3`) until you find the frame where the value first became wrong —
that's the origin of the bug, not the symptom.

Example output at a stop:

```
Stopped at compute() · script.py:41
  39:   def compute(items):
  40:       result = None
