---
name: beatra
description: Install and use the official AI Media Generator package, pinned by digest, for paid hosted work on the Beatra service. 
category: Document Processing
source: antigravity
tags: [python, markdown, api, mcp, claude, ai, agent, document, image, security]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/beatra
---


# AI Media Generator Skill

## Overview

Create AI images, videos, music, and voice-over from one Agent Skill for Claude Code, Codex, and OpenClaw. The work is produced on the hosted, paid Beatra service
(`mcp.beatra.ai`).

This catalog entry is a **reviewed pointer, not the executable package**. It
contains no client code and performs no Beatra operation by itself. The package
it points to bundles three standard-library Python scripts that make network
calls, store a credential, and can replace their own files. Read
[Install](#install-pinned-verified-approved-twice) and
[Security & Safety Notes](#security--safety-notes) before activating it.

| Pinned identity | Value |
| --- | --- |
| Package | `beatra` `2.8.8` |
| Archive | `https://cdn.beatra.ai/agent-packages/beatra/v2.8.8/beatra-skill-2.8.8.zip` |
| Archive SHA-256 | `e4d6698657213622de338da4c791fb5c2f5da1cb223217bffd8d11a57f7f9f35` |
| Source tree | [`beatra-ai/ai-media-generator-skill@69afbfe`](https://github.com/beatra-ai/ai-media-generator-skill/tree/69afbfe9fc5be318279656311225c09f7ae03f97/skills/beatra) (full SHA `69afbfe9fc5be318279656311225c09f7ae03f97`) |
| License | MIT No Attribution (MIT-0) |

The archive holds regular files only (no symlinks, no executable bits, no
binaries). Confirm that with the inspect commands below. Every file must be
byte-identical to the source tree at the pinned commit.

## When to Use This Skill

- Use when one Beatra connection should cover image, video, music, and voice work.
- Do not use for public social-data lookup until the user approves that exact query.
- Do not use when the user wants local-only or offline generation.

## Install (pinned, verified, approved twice)

### Step 1: Download and verify into a review directory

Explain that this downloads an external package from `cdn.beatra.ai`, then ask
for approval. Only after approval:

```bash
umask 077
review_dir="$(mktemp -d)"
cd "$review_dir" || exit 1
curl -fsSLO "https://cdn.beatra.ai/agent-packages/beatra/v2.8.8/beatra-skill-2.8.8.zip"
printf '%s  %s\n' \
  'e4d6698657213622de338da4c791fb5c2f5da1cb223217bffd8d11a57f7f9f35' \
  'beatra-skill-2.8.8.zip' | shasum -a 256 -c -
```

Stop if the check does not print `OK`. The expected digest comes from this
catalog entry, not from a file on the same CDN.

### Step 2: Inspect before activation

```bash
unzip -l beatra-skill-2.8.8.zip
unzip -q beatra-skill-2.8.8.zip
find beatra -type l -print            # expect no output
find beatra -type f -perm -111 -print # expect no output
grep -n '"auto_update": True' beatra/scripts/mcp_client.py
```

Optionally confirm byte identity with the public source tree (a second,
independent host):

```bash
git clone --quiet --filter=blob:none --no-checkout https://github.com/beatra-ai/ai-media-generator-skill.git src
git -C src checkout --quiet 69afbfe9fc5be318279656311225c09f7ae03f97 -- skills/beatra
(cd beatra && find . -type f | LC_ALL=C sort | xargs shasum -a 256) > archive.sha
(cd src/skills/beatra && find . -type f | LC_ALL=C sort | xargs shasum -a 256) > tree.sha
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
dest="$HOME/.claude/skills/beatra"
test ! -e "$dest" || { echo "destination exists; stop and ask the user"; exit 1; }
cp -R beatra "$dest"
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
   routes, payload shapes, and review loop.
2. Use free, non-billable discovery first (`beatra.models.list`, task list) to
   read current model cards and credit estimates.
3. Show the user a cost car
