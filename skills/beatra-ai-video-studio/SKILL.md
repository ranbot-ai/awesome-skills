---
name: beatra-ai-video-studio
description: Install and use the official Beatra AI Video Studio package, pinned by digest, for paid text-to-video, image-to-video, and video edit or extend jobs on the hosted Beatra service. 
category: AI & Agents
source: antigravity
tags: [python, markdown, api, mcp, claude, ai, agent, image, security]
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
calls and store a credential. It has no self-updater: it never downloads
code and never changes its own files. Read
[Install](#install-pinned-verified-approved-twice) and
[Security & Safety Notes](#security--safety-notes) before activating it.

| Pinned identity | Value |
| --- | --- |
| Package | `beatra-ai-video-studio` `1.3.5` |
| Source commit | [`beatra-ai/beatra-skills@b7ab8ed`](https://github.com/beatra-ai/beatra-skills/tree/b7ab8ed02980ee44b6dac62633f8d79daf0809ab/skills/beatra-ai-video-studio) (full SHA `b7ab8ed02980ee44b6dac62633f8d79daf0809ab`) |
| Package tree | `5183c76c894e650691c8bb638257dd202b23e66c` (Git tree ID of `skills/beatra-ai-video-studio` at that commit) |
| License | MIT No Attribution (MIT-0) |

The pinned tree holds regular files only (no symlinks, no executable bits, no
binaries). Confirm that with the inspect commands below.

## When to Use This Skill

- Use when the user explicitly wants a short AI video clip produced on Beatra
  and accepts that the work is paid and runs on a hosted service.
- Use when a still image should be animated, two frames interpolated, or an
  existing clip edited or extended by Beatra.
- Do not use for local-only or offline video editing, timeline assembly, or
  when the user has not agreed to send prompts and media to a third party.

## Install (pinned, verified, approved twice)

### Step 1: Fetch the pinned tree into a review directory

Explain that this fetches an external package from `github.com`, then ask
for approval. Only after approval:

```bash
set -e
umask 077
review_dir="$(mktemp -d)"
cd "$review_dir" || exit 1
git clone --quiet --filter=blob:none --no-checkout https://github.com/beatra-ai/beatra-skills.git src
git -C src checkout --quiet b7ab8ed02980ee44b6dac62633f8d79daf0809ab -- skills/beatra-ai-video-studio
test "$(git -C src rev-parse 'b7ab8ed02980ee44b6dac62633f8d79daf0809ab:skills/beatra-ai-video-studio')" = '5183c76c894e650691c8bb638257dd202b23e66c' && echo TREE-OK
```

Stop if the last command does not print `TREE-OK`. The expected commit and
tree IDs come from this catalog entry, not from the package or its website,
and Git addresses every fetched object by its hash.

### Step 2: Inspect before activation

```bash
git -C src ls-tree -r b7ab8ed02980ee44b6dac62633f8d79daf0809ab -- skills/beatra-ai-video-studio | awk '$1 != "100644"'  # expect no output
grep -n -E 'maybe_auto_update|download_update|_apply_update' src/skills/beatra-ai-video-studio/scripts/mcp_client.py  # expect no output
```

The first check lists any symlink, executable, or submodule entry; the second
finds the entry points of the self-updater that earlier versions shipped.

Report to the user what the review found: `SKILL.md`, `manifest.json`,
`install-source.json` (the one-line marker `{"schema_version":1,"source":"github"}`),
the bundled Markdown references, and `scripts/authorize.py`,
`scripts/mcp_client.py`, `scripts/uninstall.py` (Python 3.10+, standard
library only, no dependency installation, no lifecycle hooks). Summarize the
network, credential, local-state, telemetry, and version-notice behavior
listed under [Security & Safety Notes](#security--safety-notes).

The manifest and pattern scans above are only inventory aids. Before activation, read every file in the pinned tree, including each script, reference and hook, and inspect all dependency and network behavior. Do not claim source review from grep output. If complete review cannot be performed, stop before copying or executing; ask for a separate review rather than treating a digest as evidence of safety.

### Step 3: Copy in

Ask for a **second, separate** approval, because this changes agent
configuration. Then copy the reviewed tree to the host's skills directory
(Claude Code shown; use the equivalent path for other hosts):

```bash
dest="$HOME/.claude/skills/beatra-ai-video-studio"
test ! -e "$dest" && test ! -L "$dest" || { echo "destination exists; stop and ask the user"; exit 1; }
cp -R "src/skills/beatra-ai-video-studio" "$dest"
```

There is no update switch to turn off in this version.

### Step 4: Authorize as its own decision

Authorization opens a browser sign-in and stores a bearer token. Ask first.

```bash
python3 "$dest/scripts/authorize.py"
```

Start a new agent session if the host discovers skills only at startup.

## How It Works

1. Read the installed package's `SKILL.md` and its references; they define the
   video rou
