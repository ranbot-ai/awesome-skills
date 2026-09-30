---
name: ai-podcast-voiceover
description: Install and use the official AI Podcast Voiceover package, pinned by digest, for paid hosted work on the Beatra service. 
category: Document Processing
source: antigravity
tags: [python, markdown, api, mcp, claude, ai, agent, document, security]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/ai-podcast-voiceover
---


# AI Podcast Voiceover Skill

## Overview

Turn an article, notes, or a finished script into a solo podcast episode with a consistent host voice, natural pacing, pronunciation control, and an MP3 you can publish, from inside Claude Code, Codex, or OpenClaw. The work is produced on the hosted, paid Beatra service
(`mcp.beatra.ai`).

This catalog entry is a **reviewed pointer, not the executable package**. It
contains no client code and performs no Beatra operation by itself. The package
it points to bundles three standard-library Python scripts that make network
calls, store a credential, and can replace their own files. Read
[Install](#install-pinned-verified-approved-twice) and
[Security & Safety Notes](#security--safety-notes) before activating it.

| Pinned identity | Value |
| --- | --- |
| Package | `ai-podcast-voiceover` `0.1.7` |
| Archive | `https://cdn.beatra.ai/agent-packages/ai-podcast-voiceover/v0.1.7/ai-podcast-voiceover-skill-0.1.7.zip` |
| Archive SHA-256 | `571a9b48f7e32e5350a4916f502ed78c66b16f6bffdde33dda1c4c1b00996c87` |
| Source tree | [`beatra-ai/ai-podcast-voiceover-skill@ddca11e`](https://github.com/beatra-ai/ai-podcast-voiceover-skill/tree/ddca11ec6853184468eab57a5b4b3649e5293f4d/skills/ai-podcast-voiceover) (full SHA `ddca11ec6853184468eab57a5b4b3649e5293f4d`) |
| License | MIT No Attribution (MIT-0) |

The archive holds regular files only (no symlinks, no executable bits, no
binaries). Confirm that with the inspect commands below. Every file must be
byte-identical to the source tree at the pinned commit.

## When to Use This Skill

- Use when the user explicitly wants AI Podcast Voiceover audio produced on Beatra and accepts that it is paid.
- Use when they have agreed to send scripts to a third party for hosted synthesis.
- Do not use for local TTS or when no paid synthesis was approved.

## Install (pinned, verified, approved twice)

### Step 1: Download and verify into a review directory

Explain that this downloads an external package from `cdn.beatra.ai`, then ask
for approval. Only after approval:

```bash
umask 077
review_dir="$(mktemp -d)"
cd "$review_dir" || exit 1
curl -fsSLO "https://cdn.beatra.ai/agent-packages/ai-podcast-voiceover/v0.1.7/ai-podcast-voiceover-skill-0.1.7.zip"
printf '%s  %s\n' \
  '571a9b48f7e32e5350a4916f502ed78c66b16f6bffdde33dda1c4c1b00996c87' \
  'ai-podcast-voiceover-skill-0.1.7.zip' | shasum -a 256 -c -
```

Stop if the check does not print `OK`. The expected digest comes from this
catalog entry, not from a file on the same CDN.

### Step 2: Inspect before activation

```bash
unzip -l ai-podcast-voiceover-skill-0.1.7.zip
unzip -q ai-podcast-voiceover-skill-0.1.7.zip
find ai-podcast-voiceover -type l -print            # expect no output
find ai-podcast-voiceover -type f -perm -111 -print # expect no output
grep -n '"auto_update": True' ai-podcast-voiceover/scripts/mcp_client.py
```

Optionally confirm byte identity with the public source tree (a second,
independent host):

```bash
git clone --quiet --filter=blob:none --no-checkout https://github.com/beatra-ai/ai-podcast-voiceover-skill.git src
git -C src checkout --quiet ddca11ec6853184468eab57a5b4b3649e5293f4d -- skills/ai-podcast-voiceover
(cd ai-podcast-voiceover && find . -type f | LC_ALL=C sort | xargs shasum -a 256) > archive.sha
(cd src/skills/ai-podcast-voiceover && find . -type f | LC_ALL=C sort | xargs shasum -a 256) > tree.sha
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
dest="$HOME/.claude/skills/ai-podcast-voiceover"
test ! -e "$dest" || { echo "destination exists; stop and ask the user"; exit 1; }
cp -R ai-podcast-voiceover "$dest"
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
python3 "$dest/scripts/authori
