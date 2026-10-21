---
name: ai-storyboard-generator
description: Install and use the official AI Storyboard Generator package, pinned by digest, for paid hosted work on the Beatra service. 
category: AI & Agents
source: antigravity
tags: [python, markdown, api, mcp, claude, ai, agent, image, security]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/ai-storyboard-generator
---


# AI Storyboard Generator Skill

## Overview

Turn a script, scene, or ad brief into a practical shot list and one to four storyboard key-frame images, from inside Claude Code, Codex, or OpenClaw. The work is produced on the hosted, paid Beatra service
(`mcp.beatra.ai`).

This catalog entry is a **reviewed pointer, not the executable package**. It
contains no client code and performs no Beatra operation by itself. The package
it points to bundles three standard-library Python scripts that make network
calls and store a credential. It has no self-updater: it never downloads
code and never changes its own files. Read
[Install](#install-pinned-verified-approved-twice) and
[Security & Safety Notes](#security--safety-notes) before activating it.

| Pinned identity | Value |
| --- | --- |
| Package | `ai-storyboard-generator` `0.2.6` |
| Source commit | [`beatra-ai/ai-storyboard-generator-skill@4736c45`](https://github.com/beatra-ai/ai-storyboard-generator-skill/tree/4736c45d40bb0823385c1eae407aa2886cd2ff1c/skills/ai-storyboard-generator) (full SHA `4736c45d40bb0823385c1eae407aa2886cd2ff1c`) |
| Package tree | `51baed55833fe73839f598c65795c089c16f6d59` (Git tree ID of `skills/ai-storyboard-generator` at that commit) |
| License | MIT No Attribution (MIT-0) |

The pinned tree holds regular files only (no symlinks, no executable bits, no
binaries). Confirm that with the inspect commands below.

## When to Use This Skill

- Use when the user wants storyboard key frames produced on Beatra for a script, scene, or ad brief and accepts that they are paid.
- Use when they have agreed to send prompts and any reference images to a third party.
- Do not use to produce finished video footage, or when no paid render was approved; a written shot list alone needs no paid call.

## Install (pinned, verified, approved twice)

### Step 1: Fetch the pinned tree into a review directory

Explain that this fetches an external package from `github.com`, then ask
for approval. Only after approval:

```bash
set -e
umask 077
review_dir="$(mktemp -d)"
cd "$review_dir" || exit 1
git clone --quiet --filter=blob:none --no-checkout https://github.com/beatra-ai/ai-storyboard-generator-skill.git src
git -C src checkout --quiet 4736c45d40bb0823385c1eae407aa2886cd2ff1c -- skills/ai-storyboard-generator
test "$(git -C src rev-parse '4736c45d40bb0823385c1eae407aa2886cd2ff1c:skills/ai-storyboard-generator')" = '51baed55833fe73839f598c65795c089c16f6d59' && echo TREE-OK
```

Stop if the last command does not print `TREE-OK`. The expected commit and
tree IDs come from this catalog entry, not from the package or its website,
and Git addresses every fetched object by its hash.

### Step 2: Inspect before activation

```bash
git -C src ls-tree -r 4736c45d40bb0823385c1eae407aa2886cd2ff1c -- skills/ai-storyboard-generator | awk '$1 != "100644"'  # expect no output
grep -n -E 'maybe_auto_update|download_update|_apply_update' src/skills/ai-storyboard-generator/scripts/mcp_client.py  # expect no output
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
dest="$HOME/.claude/skills/ai-storyboard-generator"
test ! -e "$dest" && test ! -L "$dest" || { echo "destination exists; stop and ask the user"; exit 1; }
cp -R "src/skills/ai-storyboard-generator" "$dest"
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
   routes, payload shapes, and review loop.
2. Use free, non-billable discovery fir
