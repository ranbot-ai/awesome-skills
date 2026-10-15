---
name: ai-image-generation-studio
description: Install and use the official AI Image Generator package, pinned by digest, for paid hosted work on the Beatra service. 
category: Document Processing
source: antigravity
tags: [python, markdown, api, mcp, claude, ai, agent, document, image, security]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/ai-image-generation-studio
---


# AI Image Generator Skill

## Overview

Generate, compose, and edit product images, brand visuals, posters, social graphics, illustrations, and photo variations, from inside Claude Code, Codex, or OpenClaw. The work is produced on the hosted, paid Beatra service
(`mcp.beatra.ai`).

This catalog entry is a **reviewed pointer, not the executable package**. It
contains no client code and performs no Beatra operation by itself. The package
it points to bundles three standard-library Python scripts that make network
calls, store a credential, and can replace their own files. Read
[Install](#install-pinned-verified-approved-twice) and
[Security & Safety Notes](#security--safety-notes) before activating it.

| Pinned identity | Value |
| --- | --- |
| Package | `ai-image-generation-studio` `0.1.4` |
| Archive | `https://cdn.beatra.ai/agent-packages/ai-image-generation-studio/v0.1.4/ai-image-generation-studio-skill-0.1.4.zip` |
| Archive SHA-256 | `b357edb0f9f2546435c89cf1ef8278596e28a7629229a78fcab9804decd13682` |
| Source tree | [`beatra-ai/ai-image-generator-skill@13c7b9b`](https://github.com/beatra-ai/ai-image-generator-skill/tree/13c7b9b2a2197fb91deb6a3a1466124db620c3d1/skills/ai-image-generation-studio) (full SHA `13c7b9b2a2197fb91deb6a3a1466124db620c3d1`) |
| License | MIT No Attribution (MIT-0) |

The archive holds regular files only (no symlinks, no executable bits, no
binaries). Confirm that with the inspect commands below. Every file must be
byte-identical to the source tree at the pinned commit.

## When to Use This Skill

- Use when the user explicitly wants AI Image Generator work produced on Beatra and accepts that it is paid.
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
curl --connect-timeout 10 --max-time 60 -fsSO "https://cdn.beatra.ai/agent-packages/ai-image-generation-studio/v0.1.4/ai-image-generation-studio-skill-0.1.4.zip"
printf '%s  %s\n' \
  'b357edb0f9f2546435c89cf1ef8278596e28a7629229a78fcab9804decd13682' \
  'ai-image-generation-studio-skill-0.1.4.zip' | shasum -a 256 -c -
```

Stop if the check does not print `OK`. The expected digest comes from this
catalog entry, not from a file on the same CDN.

### Step 2: Inspect before activation

Before extraction, inspect every ZIP member name, Unix mode, declared size and total expanded size. Reject absolute/traversing paths, entries outside the intended package root, duplicate or case-colliding names, symlinks, devices and executable/binary files. Set bounded file-count, per-file and total extraction limits. Extract only after that preflight passes into the fresh private review directory; inspecting links after extraction cannot prevent an escape. A matching archive hash is an integrity check against this receipt, not permission to execute or proof of complete safety.


```bash
unzip -l ai-image-generation-studio-skill-0.1.4.zip
# After the complete member preflight passes:
unzip -q ai-image-generation-studio-skill-0.1.4.zip
find ai-image-generation-studio -type l -print            # expect no output
find ai-image-generation-studio -type f -perm -111 -print # expect no output
grep -n '"auto_update": True' ai-image-generation-studio/scripts/mcp_client.py
```

Confirm byte identity with the public source tree before activation (a second,
independent host):

```bash
git clone --quiet --filter=blob:none --no-checkout https://github.com/beatra-ai/ai-image-generator-skill.git src
git -C src checkout --quiet 13c7b9b2a2197fb91deb6a3a1466124db620c3d1 -- skills/ai-image-generation-studio
(cd ai-image-generation-studio && find . -type f | LC_ALL=C sort | xargs shasum -a 256) > archive.sha
(cd src/skills/ai-image-generation-studio && find . -type f | LC_ALL=C sort | xargs shasum -a 256) > tree.sha
cmp archive.sha tree.sha && echo IDENTICAL
```

Report to the user what the review found: `SKILL.md`, `manifest.json`, the
bundled Markdown references, and `scripts/authorize.py`,
`scripts/mcp_client.py`, `scripts/uninstall.py` (Python 3.10+, standard
library only, no dependency installation, no lifecycle hooks). Summarize the
network, credential, local-state, telemetry, and self-update behavior listed
under [Security & Safety Notes](#security--safety-notes).

### Step 3: Copy in and disable self-update before any other command

Obtain explicit authorization for this host configuration change if it is not already covered by the user's request; do not repeat an existing scoped approval. Then copy the reviewed tree to the host's skills directory
(Claude Code shown; use the equivalent path for other hosts) and immediately
turn off silent self-update for that 
