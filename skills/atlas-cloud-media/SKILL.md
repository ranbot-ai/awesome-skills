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

### 1. Discover and Validate a Model

Fetch the catalog, filter by `type` (`Image` or `Video`), and match the user's
requested capability. Read the selected entry's `schema`, verify that all
required fields are present, and show the model and billable action to the user
before submission.

Example discovery request:

```bash
curl --fail --silent --show-error \
  "https://api.atlascloud.ai/api/v1/models" \
  --output /tmp/atlas-models.json

jq -r '.data[] | select(.type == "Image") | [.model, .displayName, .schema] | @tsv' \
  /tmp/atlas-models.json
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
  > /tmp/atlas-image-request.json

curl --fail --silent --show-error \
  --request POST \
  "https://api.atlascloud.ai/api/v1/model/generateImage" \
  --header "Authorization: Bearer $ATLASCLOUD_API_KEY" \
  --header "Content-Type: application/json" \
  --data @/tmp/atlas-image-request.json \
  --output /tmp/atlas-submit.json
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
  }' > /tmp/atlas-video-request.json

curl --fail --silent --show-error \
  --request POST \
  "https://api.atlascloud.ai/api/v1/model/generateVideo" \
  --header "Authorization: Bearer $ATLASCLOUD_API_KEY" \
  --header "Content-Type: application/json" \
  --data @/tmp/atlas-video-request.json \
  --output /tmp/atlas-submit.json
```

Check that `.data.id` is a non-empty string before polling. Treat a non-2xx
response or a missing ID as submission failure; do not retry a billable request
automatically because the original task may still have been accepted.

### 3. Poll with a Deadline

Poll every three seconds. Accept `completed` or `succeeded` as success, stop on
`failed` or `timeout`, and stop after ten minutes. Preserve the prediction ID
for diagnostics, but never log request headers or the API key.

```bash
prediction_id=$(jq -er '.data.id | select(type == "string" and length > 0)' \
  /tmp/atlas-submit.json)

for attempt in $(seq 1 200); do
  sleep 3
  curl --fail --silent --show-error \
    "https://api.atlascloud.ai/api/v1/model/prediction/$prediction_id" \
    --header "Authorization: Bearer $ATLASCLOUD_API_KEY" \
    --output /tmp/atlas-prediction.json

  status=$(jq -r '.data.status // "unknown"' /tmp/atlas-prediction.json)
  case "$status" in
    completed|succeeded) break ;;
    failed|timeout)
