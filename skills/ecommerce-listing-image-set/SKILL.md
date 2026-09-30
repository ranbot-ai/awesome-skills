---
name: ecommerce-listing-image-set
description: Install and use the official Ecommerce Product Images package, pinned by digest, for paid hosted work on the Beatra service. 
category: Document Processing
source: antigravity
tags: [python, markdown, api, mcp, claude, ai, agent, document, image, security]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/ecommerce-listing-image-set
---


# Ecommerce Product Images Skill

## Overview

Turn real product photos and confirmed SKU facts into a matching ecommerce image set: a hero image, feature visuals, lifestyle scenes, size views, and in-box images, from inside Claude Code, Codex, or OpenClaw. The work is produced on the hosted, paid Beatra service
(`mcp.beatra.ai`).

This catalog entry is a **reviewed pointer, not the executable package**. It
contains no client code and performs no Beatra operation by itself. The package
it points to bundles three standard-library Python scripts that make network
calls, store a credential, and can replace their own files. Read
[Install](#install-pinned-verified-approved-twice) and
[Security & Safety Notes](#security--safety-notes) before activating it.

| Pinned identity | Value |
| --- | --- |
| Package | `ecommerce-listing-image-set` `0.2.0` |
| Archive | `https://cdn.beatra.ai/agent-packages/ecommerce-listing-image-set/v0.2.0/ecommerce-listing-image-set-skill-0.2.0.zip` |
| Archive SHA-256 | `84c0c7df4c1180212b76392a120a95f1f9b5ad4b74f73748642aeab704511b6a` |
| Source tree | [`beatra-ai/ecommerce-product-images-skill@ef9056d`](https://github.com/beatra-ai/ecommerce-product-images-skill/tree/ef9056dcb0d886ad8eb1e3a49803c1143598506c/skills/ecommerce-listing-image-set) (full SHA `ef9056dcb0d886ad8eb1e3a49803c1143598506c`) |
| License | MIT No Attribution (MIT-0) |

The archive holds regular files only (no symlinks, no executable bits, no
binaries). Confirm that with the inspect commands below. Every file must be
byte-identical to the source tree at the pinned commit.

## When to Use This Skill

- Use when the user explicitly wants Ecommerce Product Images work produced on Beatra and accepts that it is paid.
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
curl -fsSLO "https://cdn.beatra.ai/agent-packages/ecommerce-listing-image-set/v0.2.0/ecommerce-listing-image-set-skill-0.2.0.zip"
printf '%s  %s\n' \
  '84c0c7df4c1180212b76392a120a95f1f9b5ad4b74f73748642aeab704511b6a' \
  'ecommerce-listing-image-set-skill-0.2.0.zip' | shasum -a 256 -c -
```

Stop if the check does not print `OK`. The expected digest comes from this
catalog entry, not from a file on the same CDN.

### Step 2: Inspect before activation

```bash
unzip -l ecommerce-listing-image-set-skill-0.2.0.zip
unzip -q ecommerce-listing-image-set-skill-0.2.0.zip
find ecommerce-listing-image-set -type l -print            # expect no output
find ecommerce-listing-image-set -type f -perm -111 -print # expect no output
grep -n '"auto_update": True' ecommerce-listing-image-set/scripts/mcp_client.py
```

Optionally confirm byte identity with the public source tree (a second,
independent host):

```bash
git clone --quiet --filter=blob:none --no-checkout https://github.com/beatra-ai/ecommerce-product-images-skill.git src
git -C src checkout --quiet ef9056dcb0d886ad8eb1e3a49803c1143598506c -- skills/ecommerce-listing-image-set
(cd ecommerce-listing-image-set && find . -type f | LC_ALL=C sort | xargs shasum -a 256) > archive.sha
(cd src/skills/ecommerce-listing-image-set && find . -type f | LC_ALL=C sort | xargs shasum -a 256) > tree.sha
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
dest="$HOME/.claude/skills/ecommerce-listing-image-set"
test ! -e "$dest" || { echo "destination exists; stop and ask the user"; exit 1; }
cp -R ecommerce-listing-image-set "$dest"
python3 "$dest/scripts/mcp_client.py" update --auto off
```

The last command must print
`Automatic Beatra package updates are disabled.` It writes only
`~/.beatra/updates/<id>/state.json` and makes no network request. Run it
before `authorize.py`, `verify`, `tools`, `upload`, or `call`: in this
pinned version self-update is **on by default**. The setting is keyed to the
resolved install path, so repeat it after moving or re-copying the directory.

### Step
