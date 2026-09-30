---
name: ai-logo-maker
description: Install and use the official AI Logo Maker package, pinned by digest, for paid hosted work on the Beatra service. 
category: Document Processing
source: antigravity
tags: [python, markdown, api, mcp, claude, ai, agent, design, document, image]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/ai-logo-maker
---


# AI Logo Maker Skill

## Overview

Turn a brand name, industry, or reference image into logo concepts and a scalable brand mark, from inside Claude Code, Codex, or OpenClaw. The work is produced on the hosted, paid Beatra service
(`mcp.beatra.ai`).

This catalog entry is a **reviewed pointer, not the executable package**. It
contains no client code and performs no Beatra operation by itself. The package
it points to bundles three standard-library Python scripts that make network
calls, store a credential, and can replace their own files. Read
[Install](#install-pinned-verified-approved-twice) and
[Security & Safety Notes](#security--safety-notes) before activating it.

| Pinned identity | Value |
| --- | --- |
| Package | `ai-logo-maker` `0.1.7` |
| Archive | `https://cdn.beatra.ai/agent-packages/ai-logo-maker/v0.1.7/ai-logo-maker-skill-0.1.7.zip` |
| Archive SHA-256 | `a6ce019ccb55abf017d6c68233dc9804e8534d5cb4e1c27c2646fb31f59eac55` |
| Source tree | [`beatra-ai/ai-logo-maker-skill@89bf762`](https://github.com/beatra-ai/ai-logo-maker-skill/tree/89bf762b964f67b77eb0af34d832aab19188f557/skills/ai-logo-maker) (full SHA `89bf762b964f67b77eb0af34d832aab19188f557`) |
| License | MIT No Attribution (MIT-0) |

The archive holds regular files only (no symlinks, no executable bits, no
binaries). Confirm that with the inspect commands below. Every file must be
byte-identical to the source tree at the pinned commit.

## When to Use This Skill

- Use when the user explicitly wants AI Logo Maker work produced on Beatra and accepts that it is paid.
- Use when they have agreed to send prompts and any reference images to a third party.
- Do not use for local-only image editing or when no paid render was approved.

## Install (pinned, verified, approved twice)

### Step 1: Download and verify into a review directory

Explain that this downloads an external package from `cdn.beatra.ai`, then ask
for approval. Only after approval:

```bash
umask 077
review_dir="$(mktemp -d)"
cd "$review_dir" || exit 1
curl -fsSLO "https://cdn.beatra.ai/agent-packages/ai-logo-maker/v0.1.7/ai-logo-maker-skill-0.1.7.zip"
printf '%s  %s\n' \
  'a6ce019ccb55abf017d6c68233dc9804e8534d5cb4e1c27c2646fb31f59eac55' \
  'ai-logo-maker-skill-0.1.7.zip' | shasum -a 256 -c -
```

Stop if the check does not print `OK`. The expected digest comes from this
catalog entry, not from a file on the same CDN.

### Step 2: Inspect before activation

```bash
unzip -l ai-logo-maker-skill-0.1.7.zip
unzip -q ai-logo-maker-skill-0.1.7.zip
find ai-logo-maker -type l -print            # expect no output
find ai-logo-maker -type f -perm -111 -print # expect no output
grep -n '"auto_update": True' ai-logo-maker/scripts/mcp_client.py
```

Optionally confirm byte identity with the public source tree (a second,
independent host):

```bash
git clone --quiet --filter=blob:none --no-checkout https://github.com/beatra-ai/ai-logo-maker-skill.git src
git -C src checkout --quiet 89bf762b964f67b77eb0af34d832aab19188f557 -- skills/ai-logo-maker
(cd ai-logo-maker && find . -type f | LC_ALL=C sort | xargs shasum -a 256) > archive.sha
(cd src/skills/ai-logo-maker && find . -type f | LC_ALL=C sort | xargs shasum -a 256) > tree.sha
cmp archive.sha tree.sha && echo IDENTICAL
```

Report to the user what the review found: `SKILL.md`, `manifest.json`, the
bundled Markdown references, and `scripts/authorize.py`,
`scripts/mcp_client.py`, `scripts/uninstall.py` (Python 3.10+, standard
library only, no dependency installation, no lifecycle hooks). Summarize the
network, credential, local-state, telemetry, and self-update behavior listed
under [Security & Safety Notes](#security--safety-notes).

### Step 3: Copy in and disable self-update before any other command

Ask for a **second, separate** approval, because this changes agent
configuration. Then copy the reviewed tree to the host's skills directory
(Claude Code shown; use the equivalent path for other hosts) and immediately
turn off silent self-update for that exact path:

```bash
dest="$HOME/.claude/skills/ai-logo-maker"
test ! -e "$dest" || { echo "destination exists; stop and ask the user"; exit 1; }
cp -R ai-logo-maker "$dest"
python3 "$dest/scripts/mcp_client.py" update --auto off
```

The last command must print
`Automatic Beatra package updates are disabled.` It writes only
`~/.beatra/updates/<id>/state.json` and makes no network request. Run it
before `authorize.py`, `verify`, `tools`, `upload`, or `call`: in this
pinned version self-update is **on by default**. The setting is keyed to the
resolved install path, so repeat it after moving or re-copying the directory.

### Step 4: Authorize as its own decision

Authorization opens a browser sign-in and stores a bearer token. Ask first.

```bash
python3 "$dest/scripts/authorize.py"
```

Start a new agent session if the host discovers skills only at startup.

## How It Works

1. Read the installed package's `SKILL.md` and its references; they define the
   routes, payload shapes, and rev
