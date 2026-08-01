---
name: cowork-to-code-bridge
description: Use an already-installed, independently verified cowork-to-code bridge to run narrowly approved actions on the user's own macOS, Linux, or WSL2 machine through a local file queue. 
category: Development & Code Tools
source: antigravity
tags: [python, api, mcp, claude, ai, agent]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/cowork-to-code-bridge
---


# cowork-to-code-bridge

Use this skill only when the user explicitly asks to operate on a machine they
own or administer and the required work cannot be completed in the current
sandbox. The bridge queues a named script through a shared local directory; it
does not make a local task safe merely because it opens no inbound port.

> [!WARNING]
> The bridge daemon and its scripts run with the local account's permissions.
> They can access local files, credentials, processes, and outbound network
> connections available to that account. Treat every queued task as execution
> on the user's real machine.

## When to Use

Use this skill only when all of the following are true:

- the user explicitly requested work on their own machine;
- the bridge was already installed and independently verified by the owner;
- the exact local path, action, permission scope, and expected output are known;
- the action cannot be completed safely in the current sandbox;
- a fixed approved script can perform the task, or the user explicitly approves
  the stronger `run_claude.sh` boundary described below.

Examples include an explicitly requested disk-health check, repository status,
or a bounded edit in one named worktree. Do not activate this skill from a
generic request to write code, reason about a problem, or edit files already
available in the current environment.

## Do Not Bootstrap from Mutable Upstream Instructions

This skill does not endorse the upstream one-line installer. The reviewed
upstream snapshot is:

```text
commit: 97f515d425df587c281effb02cda9ad0fd470790
install.sh sha256: 887f5fa18b49602a119e01d58c80b7ca63832fb339aa513aa72f5a1faadc14f8
LICENSE sha256: 43b7d2c43544fb06c3ebb6529073f3536e5e2ef5a41198e0c59e0a50c088b534
```

The installer at that commit still resolves mutable inputs: a PyPI range,
GitHub `main` fallbacks, a `bridge_client.py` fetch from `main`, optional
Homebrew/Python installation, and optional Claude CLI installation. Pinning only
the outer `install.sh` therefore does not pin the installed system.

For a new installation, stop and ask the owner to perform an independent
installer and dependency audit or wait for an upstream immutable installation
path. Do not download and execute the installer, pipe remote content to a shell,
or silently patch and run it from this skill.

To inspect the reviewed snapshot without installing it:

```bash
git init cowork-to-code-bridge-review
cd cowork-to-code-bridge-review
git remote add origin https://github.com/abhinaykrupa/cowork-to-code-bridge.git
git fetch --depth=1 origin 97f515d425df587c281effb02cda9ad0fd470790
git checkout --detach FETCH_HEAD
test "$(git rev-parse HEAD)" = "97f515d425df587c281effb02cda9ad0fd470790"
shasum -a 256 install.sh LICENSE
```

Inspection is read-only evidence, not authorization to install.

## Required Machine-Side Preconditions

Before queueing any task, require the owner to confirm all of these:

1. `BRIDGE_ROOT` is an absolute path owned by the local account and is not
   group- or world-writable.
2. The token file and queue/result directories are owner-only; no symlink or
   shared-directory indirection is present.
3. `cowork-to-code-bridge-selfcheck` succeeds on the machine.
4. The daemon runs in a dedicated environment with unrelated API keys and cloud
   credentials removed. Never assume ambient credentials are safe.
5. `BRIDGE_ALLOW_UNAUTH` is not enabled.
6. `BRIDGE_CLAUDE_AUTOINSTALL=0` is set so a queued task cannot install another
   tool as a side effect.
7. `BRIDGE_PERMISSION_CEILING` is set to an exact valid value such as `readonly`
   or `edit`, and startup logs confirm that ceiling. An invalid value is not a
   safe ceiling.
8. `CLAUDE_FLAGS` is unset, or the owner has independently verified that every
   configured flag is at least as restrictive as the requested scope. Upstream
   allows this variable to override caller-supplied permission flags, so the
   request's `permission_scope` alone is not evidence of confinement. When the
   variable is unset, confirm the generated scope mapping in task logs. When it
   is set, inspect the service environment and configuration directly; logs
   only show that the caller scope was overridden, not the effective flags.
9. A per-task budget ceiling and bounded output retention are configured.

If any precondition is unknown, stop instead of probing or repairing the
machine automatically.

## Core API

```python
from cowork_to_code_bridge import (
    call_remote,
    cancel_task,
    poll_task_result,
    queue_task,
)
```

| Function | Behavior |
|---|---|
| `call_remote` | Run one short, fixed approved script and wait. |
| `queue_task` | Queue bounded work and return a `task_id`. |
| `poll_task_result` | Read the current result without repeating the task. |
| `cancel_task` | Cancel queued work or signal an in-flight process group. |

Use `queue_task` for anything that may exceed roughly 30 seconds. Always use a
stable, operation-specific `idempotency_key` for state-chan
