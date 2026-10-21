---
name: ai-photo-restyler
description: Install and use the official Photo to Anime package, pinned by digest, for paid hosted work on the Beatra service. 
category: AI & Agents
source: antigravity
tags: [python, markdown, api, mcp, claude, ai, agent, image, security, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/ai-photo-restyler
---


# Photo to Anime Skill

## Overview

Turn a photo into anime, manga, comic, cartoon, watercolor, clay, or 3D character art then review likeness and style consistency across the set rather than assuming they are preserved, from inside Claude Code, Codex, or OpenClaw. The work is produced on the hosted, paid Beatra service
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
| Package | `ai-photo-restyler` `0.2.2` |
| Source commit | [`beatra-ai/photo-to-anime-skill@c2d3fbf`](https://github.com/beatra-ai/photo-to-anime-skill/tree/c2d3fbfffd9c0a04de5672ff8764f88fb13904ea/skills/ai-photo-restyler) (full SHA `c2d3fbfffd9c0a04de5672ff8764f88fb13904ea`) |
| Package tree | `32cb74bf0ecd7caed1983d514940bdefd96b2a2c` (Git tree ID of `skills/ai-photo-restyler` at that commit) |
| License | MIT No Attribution (MIT-0) |

The pinned tree holds regular files only (no symlinks, no executable bits, no
binaries). Confirm that with the inspect commands below.

## When to Use This Skill

- Use when the user explicitly wants Photo to Anime work produced on Beatra and accepts that it is paid.
- Use when they have agreed to send prompts and any reference images to a third party.
- Do not use for local-only image editing or when no paid render was approved.

## Install (pinned, verified, approved twice)

### Step 1: Fetch the pinned tree into a review directory

Explain that this fetches an external package from `github.com`, then ask
for approval. Only after approval:

```bash
set -e
umask 077
review_dir="$(mktemp -d)"
cd "$review_dir" || exit 1
git clone --quiet --filter=blob:none --no-checkout https://github.com/beatra-ai/photo-to-anime-skill.git src
git -C src checkout --quiet c2d3fbfffd9c0a04de5672ff8764f88fb13904ea -- skills/ai-photo-restyler
test "$(git -C src rev-parse 'c2d3fbfffd9c0a04de5672ff8764f88fb13904ea:skills/ai-photo-restyler')" = '32cb74bf0ecd7caed1983d514940bdefd96b2a2c' && echo TREE-OK
```

Stop if the last command does not print `TREE-OK`. The expected commit and
tree IDs come from this catalog entry, not from the package or its website,
and Git addresses every fetched object by its hash.

### Step 2: Inspect before activation

```bash
git -C src ls-tree -r c2d3fbfffd9c0a04de5672ff8764f88fb13904ea -- skills/ai-photo-restyler | awk '$1 != "100644"'  # expect no output
grep -n -E 'maybe_auto_update|download_update|_apply_update' src/skills/ai-photo-restyler/scripts/mcp_client.py  # expect no output
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
dest="$HOME/.claude/skills/ai-photo-restyler"
test ! -e "$dest" && test ! -L "$dest" || { echo "destination exists; stop and ask the user"; exit 1; }
cp -R "src/skills/ai-photo-restyler" "$dest"
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
2. Use free, non-billable discovery first (`beatra.models.list`, task list) to
   read current model cards and credit estimates.
