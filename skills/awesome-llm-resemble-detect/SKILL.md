---
name: resemble-detect
description: Deepfake detection and media safety — detect AI-generated audio, images, video, and text, trace synthesis sources, apply watermarks, verify speaker identity, and analyze media intelligence using Res
category: Document Processing
source: awesome-llm
tags: [api, mcp, ai, workflow, video, image, resemble, detect]
url: https://github.com/Prat011/awesome-llm-skills/tree/master/resemble-detect
---


# Resemble Detect — Deepfake Detection & Media Safety

Analyze audio, image, video, and text for synthetic manipulation, AI-generated content, watermarks, speaker identity, and media intelligence using the Resemble AI platform.

## Core Principle — THE IRON LAW

**"NEVER DECLARE MEDIA AS REAL OR FAKE WITHOUT A COMPLETED DETECTION RESULT."**

Do not guess, infer, or speculate about media authenticity. Every authenticity claim must be backed by a completed Resemble detect job with a returned `label`, `score`, and `status: "completed"`. If the detection is still `processing`, wait. If it `failed`, say so — do not substitute your own judgment.

## When to Use

Use this skill whenever the user's request involves any of these:

- Checking if audio, video, image, or text is AI-generated or manipulated
- Detecting deepfakes in any media format
- Verifying media authenticity or provenance
- Identifying which AI platform synthesized audio (source tracing)
- Applying or detecting watermarks on media
- Analyzing media for speaker info, emotion, transcription, or misinformation
- Asking natural-language questions about detection results
- Matching or verifying speaker identity against known voice profiles
- Detecting AI-generated or machine-written text
- Any mention of: "deepfake", "fake detection", "synthetic media", "voice verification", "watermark", "media forensics", "authenticity check", "source tracing", "is this real", "AI-written text", "text detection"

**Do NOT use** for text-to-speech generation, voice cloning, or speech-to-text transcription — those are separate Resemble capabilities.

## Capability Decision Tree

| User wants to...                                      | Use this                  | API endpoint               |
|-------------------------------------------------------|---------------------------|----------------------------|
| Check if media is AI-generated / deepfake             | **Deepfake Detection**    | `POST /detect`             |
| Know *which AI platform* made fake audio              | **Audio Source Tracing**   | `POST /detect` with flag   |
| Get speaker info, emotion, transcription from media   | **Intelligence**          | `POST /intelligence`       |
| Ask questions about a completed detection             | **Detect Intelligence**   | `POST /detects/{uuid}/intelligence` |
| Apply an invisible watermark to media                 | **Watermark Apply**       | `POST /watermark/apply`    |
| Check if media contains a watermark                   | **Watermark Detect**      | `POST /watermark/detect`   |
| Verify a speaker's identity against known profiles    | **Identity Search**       | `POST /identity/search`    |
| Check if text is AI-generated                         | **Text Detection**        | `POST /text_detect`        |
| Create a voice identity profile for future matching   | **Identity Create**       | `POST /identity`           |

When multiple capabilities apply (e.g., user wants deepfake detection AND intelligence), combine them in a single `POST /detect` call using the `intelligence: true` flag rather than making separate requests.

## Required Setup

- **API Key**: Bearer token from the Resemble AI dashboard
- **Base URL**: `https://app.resemble.ai/api/v2`
- **Auth Header**: `Authorization: Bearer <RESEMBLE_API_KEY>`
- **Media Requirement**: All media must be at a publicly accessible HTTPS URL

If the user provides a local file path instead of a URL, inform them the file must be hosted at a public HTTPS URL first. Do not attempt to upload local files to the API.

## MCP Tools Available

When the Resemble MCP server is connected, use these tools instead of raw API calls:

| Tool                      | Purpose                                           |
|---------------------------|---------------------------------------------------|
| `resemble_docs_lookup`    | Get comprehensive docs for any detect sub-topic   |
| `resemble_search`         | Search across all documentation                   |
| `resemble_api_endpoint`   | Get exact OpenAPI spec for any endpoint            |
| `resemble_api_search`     | Find endpoints by keyword                         |
| `resemble_get_page`       | Read specific documentation pages                 |
| `resemble_list_topics`    | List all available topics                         |

**Tool usage pattern**: Use `resemble_docs_lookup` with topic `"detect"` to get the full picture, then `resemble_api_endpoint` for exact request/response schemas before making API calls.

---

## Phase 1: Deepfake Detection

The core capability. Submit any audio, image, or video for AI-generated content analysis.

### Submit a Detection

```
POST /detect
Content-Type: application/json
Authorization: Bearer <API_KEY>

{
  "url": "https://example.com/media.mp4",
  "visualize": true,
  "intelligence": true,
  "audio_source_tracing": true
}
```

**Parameters:**

| Parameter              | Type    | Required | Description                                        
