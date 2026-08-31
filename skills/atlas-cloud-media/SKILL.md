---
name: atlas-cloud-media
description: Generate Atlas Cloud images and videos through its asynchronous media API with schema-first model selection and credential-safe polling. 
category: AI & Agents
source: antigravity
tags: [api, claude, ai, workflow, image, security, aws, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/atlas-cloud-media
---


# Atlas Cloud Media

## Overview

Use Atlas Cloud's asynchronous media API to generate images or videos. This
source-only skill describes model discovery, schema validation, task
submission, bounded polling, and safe output retrieval; it does not bundle an
SDK, executable, or hosted runtime.

## When to Use This Skill

- Use when the user explicitly asks to generate an image or video with Atlas
  Cloud.
- Use when an existing workflow needs an Atlas Cloud image or video generation
  request and can make HTTPS calls.
- Use when model-specific parameters must be discovered before submission.
- Do not use this skill for OpenAI-compatible text chat; that API has a
  different base URL and contract.

## Preconditions

1. Confirm the user is authorized to send the prompt and any reference media
   to a third-party service.
2. Explain that generation is paid and obtain approval before submitting a
   billable request.
3. Require `ATLASCLOUD_API_KEY` to be present in the environment. Never ask the
   user to paste it into chat, source files, command history, or logs.
4. Confirm the output directory and whether the user wants image generation,
   video generation, or both.

## API Contract

| Operation | Method and endpoint |
| --- | --- |
| List models | `GET https://api.atlascloud.ai/api/v1/models` |
| Generate image | `POST https://api.atlascloud.ai/api/v1/model/generateImage` |
| Generate video | `POST https://api.atlascloud.ai/api/v1/model/generateVideo` |
| Poll task | `GET https://api.atlascloud.ai/api/v1/model/prediction/{id}` |

Generation and polling requests use these headers:

```text
Authorization: Bearer $ATLASCLOUD_API_KEY
Content-Type: application/json
```

The model catalog is public. Each catalog entry includes a `schema` URL; fetch
that schema and validate parameters against it before sending a paid request.
Do not guess parameters from another model, because names such as `size`,
`ratio`, `aspect_ratio`, `image`, and `image_url` are model-specific.

## Workflow

### 0. Create a Private Per-Run Workspace

Run the remaining shell snippets in the same shell session. Create a private
directory before writing prompts, responses, prediction IDs, or signed URLs;
the parameter expansion in later steps fails closed when this setup was skipped.

```bash
umask 077
atlas_tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/atlas-cloud-media.XXXXXXXX") || exit 1
chmod 700 -- "$atlas_tmp_dir"
trap 'rm -rf -- "$atlas_tmp_dir"' EXIT
```

### 1. Discover and Validate a Model

Fetch the catalog, filter by `type` (`Image` or `Video`), and match the user's
requested capability. Read the selected entry's `schema`, verify that all
required fields are present, and show the model and billable action to the user
before submission.

Example discovery request:

```bash
curl --fail --silent --show-error \
  "https://api.atlascloud.ai/api/v1/models" \
  --output "${atlas_tmp_dir:?run private workspace setup first}/models.json"

jq -r '.data[] | select(.type == "Image") | [.model, .displayName, .schema] | @tsv' \
  "$atlas_tmp_dir/models.json"
```

### 2. Submit One Generation Task

Build the JSON body in a file so that quoting is deterministic and request
details can be reviewed without exposing the API key.

Image example using a catalog-confirmed model:

```bash
jq -n \
  --arg model "qwen-image-3.0/text-to-image" \
  --arg prompt "A paper-cut city map in blue and white, clean editorial style" \
  '{model: $model, prompt: $prompt, size: "1024*1024", n: 1}' \
  > "${atlas_tmp_dir:?run private workspace setup first}/request.json"

curl --fail --silent --show-error \
  --request POST \
  "https://api.atlascloud.ai/api/v1/model/generateImage" \
  --header "Authorization: Bearer $ATLASCLOUD_API_KEY" \
  --header "Content-Type: application/json" \
  --data @"$atlas_tmp_dir/request.json" \
  --output "$atlas_tmp_dir/submit.json"
```

Video example using a catalog-confirmed model:

```bash
jq -n \
  --arg model "bytedance/seedance-2.0-fast/text-to-video" \
  --arg prompt "A small paper boat crossing a calm pond, locked camera" \
  '{
    model: $model,
    prompt: $prompt,
    duration: 4,
    resolution: "480p",
    ratio: "16:9",
    generate_audio: false,
    watermark: false
  }' > "${atlas_tmp_dir:?run private workspace setup first}/request.json"

curl --fail --silent --show-error \
  --request POST \
  "https://api.atlascloud.ai/api/v1/model/generateVideo" \
  --header "Authorization: Bearer $ATLASCLOUD_API_KEY" \
  --header "Content-Type: application/json" \
  --data @"$atlas_tmp_dir/request.json" \
  --output "$atlas_tmp_dir/submit.json"
```

Check that `.data.id` is a non-empty string before polling. Treat a non-2xx
response or a missing ID as submission failure; do not retry a billable request
automatically because the original task may still have been accepted.

### 3. Poll with a Deadline

Poll every three seconds. Accept `completed` or `succeeded` as success, stop on
`failed` or `timeout`, and stop after ten minutes. Preserve the pr
