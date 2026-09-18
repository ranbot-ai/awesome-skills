---
name: beatra-ai-video-studio
description: Install and use the official Beatra AI Video Studio package, pinned by digest, for paid text-to-video, image-to-video, and video edit or extend jobs on the hosted Beatra service. 
category: Document Processing
source: antigravity
tags: [python, markdown, api, mcp, claude, ai, agent, document, image, security]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/beatra-ai-video-studio
---


# Beatra AI Video Studio

## Overview

Beatra AI Video Studio is Beatra's official agent package for short AI video
work: text-to-video, image-to-video, first/last-frame interpolation,
reference-guided generation, and editing or extending an existing clip. The
video is produced on the hosted, paid Beatra service (`mcp.beatra.ai`).

This catalog entry is a **reviewed pointer, not the executable package**. It
contains no client code and performs no Beatra operation by itself. The package
it points to bundles three standard-library Python scripts that make network
calls, store a credential, and can replace their own files. Read
[Install](#install-pinned-verified-approved-twice) and
[Security & Safety Notes](#security--safety-notes) before activating it.

| Pinned identity | Value |
| --- | --- |
| Package | `beatra-ai-video-studio` `1.2.5` |
| Archive | `https://cdn.beatra.ai/agent-packages/beatra-ai-video-studio/v1.2.5/beatra-ai-video-studio-skill-1.2.5.zip` |
| Archive SHA-256 | `679a3ddc06c7be631ef31f002f918465a26f17a189ffac723f45dfd348e1fc4a` |
| Source tree | [`beatra-ai/beatra-skills@95d662f`](https://github.com/beatra-ai/beatra-skills/tree/95d662f7aeddd6e2aa6da9e14f9c985e3f6b914d/skills/beatra-ai-video-studio) (full SHA `95d662f7aeddd6e2aa6da9e14f9c985e3f6b914d`) |
| License | MIT No Attribution (MIT-0) |

The archive holds 17 regular files (no symlinks, no executable bits, no
binaries), and every file is byte-identical to the source tree at that commit.

## When to Use This Skill

- Use when the user explicitly wants a short AI video clip produced on Beatra
  and accepts that the work is paid and runs on a hosted service.
- Use when a still image should be animated, two frames interpolated, or an
  existing clip edited or extended by Beatra.
- Do not use for local-only or offline video editing, timeline assembly, or
  when the user has not agreed to send prompts and media to a third party.

## Install (pinned, verified, approved twice)

### Step 1: Download and verify into a review directory

Explain that this downloads an external package from `cdn.beatra.ai`, then ask
for approval. Only after approval:

```bash
umask 077
review_dir="$(mktemp -d)"
cd "$review_dir" || exit 1
curl -fsSLO "https://cdn.beatra.ai/agent-packages/beatra-ai-video-studio/v1.2.5/beatra-ai-video-studio-skill-1.2.5.zip"
printf '%s  %s\n' \
  '679a3ddc06c7be631ef31f002f918465a26f17a189ffac723f45dfd348e1fc4a' \
  'beatra-ai-video-studio-skill-1.2.5.zip' | shasum -a 256 -c -
```

Stop if the check does not print `OK`. The expected digest comes from this
catalog entry, not from a file on the same CDN.

### Step 2: Inspect before activation

```bash
unzip -l beatra-ai-video-studio-skill-1.2.5.zip
unzip -q beatra-ai-video-studio-skill-1.2.5.zip
find beatra-ai-video-studio -type l -print            # expect no output
find beatra-ai-video-studio -type f -perm -111 -print # expect no output
grep -n '"auto_update": True' beatra-ai-video-studio/scripts/mcp_client.py
```

Optionally confirm byte identity with the public source tree (a second,
independent host):

```bash
git clone --quiet --filter=blob:none --no-checkout https://github.com/beatra-ai/beatra-skills.git src
git -C src checkout --quiet 95d662f7aeddd6e2aa6da9e14f9c985e3f6b914d -- skills/beatra-ai-video-studio
(cd beatra-ai-video-studio && find . -type f | LC_ALL=C sort | xargs shasum -a 256) > archive.sha
(cd src/skills/beatra-ai-video-studio && find . -type f | LC_ALL=C sort | xargs shasum -a 256) > tree.sha
cmp archive.sha tree.sha && echo IDENTICAL
```

Report to the user what the review found: `SKILL.md`, `manifest.json`, 12
Markdown references, and `scripts/authorize.py`, `scripts/mcp_client.py`,
`scripts/uninstall.py` (Python 3.10+, standard library only, no dependency
installation, no lifecycle hooks). Summarize the network, credential,
local-state, telemetry, and self-update behavior listed under
[Security & Safety Notes](#security--safety-notes).

### Step 3: Copy in and disable self-update before any other command

Ask for a **second, separate** approval, because this changes agent
configuration. Then copy the reviewed tree to the host's skills directory
(Claude Code shown; use the equivalent path for other hosts) and immediately
turn off silent self-update for that exact path:

```bash
dest="$HOME/.claude/skills/beatra-ai-video-studio"
test ! -e "$dest" || { echo "destination exists; stop and ask the user"; exit 1; }
cp -R beatra-ai-video-studio "$dest"
python3 "$dest/scripts/mcp_client.py" update --auto off
```

The last command must print
`Automatic Beatra package updates are disabled.` It writes only
`~/.beatra/updates/<id>/state.json` and makes no network request. Run it
before `authorize.py`, `verify`, `tools`, `upload`, or `call`: in version 1.2.5
self-update is **on by default** (see below). The setting is keyed to the
resolved install path, so repeat it after moving or re-copying the directory.

### Step 4: Authorize as its own decision

Authorization opens a b
