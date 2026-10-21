---
name: ai-multilingual-dubbing
description: Install and use the official Multilingual Voiceover package, pinned by digest, for paid hosted work on the Beatra service. 
category: AI & Agents
source: antigravity
tags: [python, markdown, api, mcp, claude, ai, agent, security]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/ai-multilingual-dubbing
---


# Multilingual Voiceover Skill

## Overview

Create reviewable voice-over audio for each language from your per-language scripts, with voices cast for each market, pronunciation and timing pilots first, and delivery organized by language and segment, from inside Claude Code, Codex, or OpenClaw. The work is produced on the hosted, paid Beatra service
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
| Package | `ai-multilingual-dubbing` `0.2.7` |
| Source commit | [`beatra-ai/multilingual-voiceover-skill@bcd5d93`](https://github.com/beatra-ai/multilingual-voiceover-skill/tree/bcd5d938b872bb50b421f752e1acba29d07965e5/skills/ai-multilingual-dubbing) (full SHA `bcd5d938b872bb50b421f752e1acba29d07965e5`) |
| Package tree | `527128d0691b8552b3e446609ce2d016353f5882` (Git tree ID of `skills/ai-multilingual-dubbing` at that commit) |
| License | MIT No Attribution (MIT-0) |

The pinned tree holds regular files only (no symlinks, no executable bits, no
binaries). Confirm that with the inspect commands below.

## When to Use This Skill

- Use when the user explicitly wants Multilingual Voiceover audio produced on Beatra and accepts that it is paid.
- Use when they have agreed to send scripts to a third party for hosted synthesis.
- Do not use for local TTS or when no paid synthesis was approved.

## Install (pinned, verified, approved twice)

### Step 1: Fetch the pinned tree into a review directory

Explain that this fetches an external package from `github.com`, then ask
for approval. Only after approval:

```bash
set -e
umask 077
review_dir="$(mktemp -d)"
cd "$review_dir" || exit 1
git clone --quiet --filter=blob:none --no-checkout https://github.com/beatra-ai/multilingual-voiceover-skill.git src
git -C src checkout --quiet bcd5d938b872bb50b421f752e1acba29d07965e5 -- skills/ai-multilingual-dubbing
test "$(git -C src rev-parse 'bcd5d938b872bb50b421f752e1acba29d07965e5:skills/ai-multilingual-dubbing')" = '527128d0691b8552b3e446609ce2d016353f5882' && echo TREE-OK
```

Stop if the last command does not print `TREE-OK`. The expected commit and
tree IDs come from this catalog entry, not from the package or its website,
and Git addresses every fetched object by its hash.

### Step 2: Inspect before activation

```bash
git -C src ls-tree -r bcd5d938b872bb50b421f752e1acba29d07965e5 -- skills/ai-multilingual-dubbing | awk '$1 != "100644"'  # expect no output
grep -n -E 'maybe_auto_update|download_update|_apply_update' src/skills/ai-multilingual-dubbing/scripts/mcp_client.py  # expect no output
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
dest="$HOME/.claude/skills/ai-multilingual-dubbing"
test ! -e "$dest" && test ! -L "$dest" || { echo "destination exists; stop and ask the user"; exit 1; }
cp -R "src/skills/ai-multilingual-dubbing" "$dest"
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
2. Use free, non-billable dis
