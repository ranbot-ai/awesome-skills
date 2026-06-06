---
name: 2slides-ppt-generator
description: AI-powered presentation generation via the 2slides API — create slides from text, match a reference image style, summarize documents into decks, add AI voice narration, and export pages/audio. Use f
category: Document Processing
source: antigravity
tags: [python, pdf, docx, api, mcp, claude, ai, workflow, template, design]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/2slides-ppt-generator
---


# 2slides Presentation Generation

## Overview

Generate professional presentations using the 2slides AI API. The skill supports content-based generation (theme-driven Fast PPT), style matching from a reference image, custom PDF design, document summarization, AI voice narration, and exporting pages/audio. It returns both an interactive slide URL and a downloadable PDF.

This skill is adapted from the official 2slides skill repository ([`2slides/slides-generation-2slides-skills`](https://github.com/2slides/slides-generation-2slides-skills)). It calls the hosted 2slides API and requires the user's own API key and credits.

## When to Use This Skill

- Use when the user asks to "create a presentation", "make slides", or "generate a deck" from text or an outline.
- Use when the user wants slides that match the style of a reference image ("create slides like this image").
- Use when the user wants custom-designed PDF slides without a reference image.
- Use when the user uploads a document and asks to "create slides from this document".
- Use when the user wants to add AI voice narration to generated slides, or export slides as PNG images and narration as WAV audio.
- Use when the user asks "what themes are available?" or wants to browse/select a theme.

## Setup Requirements

Users must have a 2slides API key and credits:

1. **Get API Key:** Visit https://2slides.com/api to create an account and API key
   - New users receive **500 free credits** (~50 Fast PPT pages)
2. **Purchase Credits (Optional):** Visit https://2slides.com/pricing to buy additional credits
   - Pay-as-you-go, no subscriptions
   - Credits never expire
   - Up to 20% off on larger packages
3. **Set API Key:** Store the key in environment variable: `SLIDES_2SLIDES_API_KEY`

```bash
export SLIDES_2SLIDES_API_KEY="your_api_key_here"
```

**Credit Costs:**
- Fast PPT: 10 credits/page
- Nano Banana 1K/2K: 100 credits/page
- Nano Banana 4K: 200 credits/page
- Voice Narration: 210 credits/page
- Download Export: FREE

See [references/pricing.md](references/pricing.md) for detailed pricing information.

## Workflow Decision Tree

Choose the appropriate approach based on the user's request:

```
User Request
│
├─ "Create slides from this content/text"
│  └─> Use Content-Based Generation (Section 1)
│
├─ "Create slides like this image"
│  └─> Use Reference Image Generation (Section 2)
│
├─ "Create custom designed slides" or "Create PDF slides"
│  └─> Use Custom PDF Generation (Section 3)
│
├─ "Create slides from this document"
│  └─> Use Document Summarization (Section 4)
│
├─ "Add voice narration" or "Generate audio for slides"
│  └─> Use Voice Narration (Section 5)
│
├─ "Download slides as images" or "Export slides and voices"
│  └─> Use Download Export (Section 6)
│
└─ "Search for themes" or "What themes are available?"
   └─> Use Theme Search (Section 7)
```

---

## 1. Content-Based Generation

Generate slides from user-provided text content.

### When to Use
- User provides content directly in their message
- User says "create a presentation about X"
- User provides structured outline or bullet points

### Workflow

**Step 1: Prepare Content**

Structure the content clearly for best results:

```
Title: [Main Topic]

Section 1: [Subtopic]
- Key point 1
- Key point 2
- Key point 3

Section 2: [Subtopic]
- Key point 1
- Key point 2
```

**Step 2: Choose Theme (Required)**

Search for an appropriate theme (themeId is required):

```bash
python scripts/search_themes.py --query "business"
python scripts/search_themes.py --query "professional"
python scripts/search_themes.py --query "creative"
```

Pick a theme ID from the results.

**Step 3: Generate Slides**

Use the `generate_slides.py` script with the theme ID:

```bash
# Basic generation (theme ID required)
python scripts/generate_slides.py --content "Your content here" --theme-id "theme123"

# In different language
python scripts/generate_slides.py --content "Your content" --theme-id "theme123" --language "Spanish"

# Async mode for longer presentations
python scripts/generate_slides.py --content "Your content" --theme-id "theme123" --mode async
```

**Step 4: Handle Results**

**Sync mode response:**
```json
{
  "slideUrl": "https://2slides.com/slides/abc123",
  "pdfUrl": "https://2slides.com/slides/abc123/download",
  "status": "completed"
}
```

Provide both URLs to the user:
- `slideUrl`: Interactive online slides
- `pdfUrl`: Downloadable PDF version

**Async mode response:**
```json
{
  "jobId": "job123",
  "status": "pending"
}
```

Poll for results:
```bash
python scripts/get_job_status.py --job-id "job123"
```

---

## 2. Reference Image Generation

Generate slides that match the style of a reference image.

### When to Use
- User provides an image URL and says "create slides like this"
- User wants to match existing brand/design style
- User has a template image they want to emulate

### Workflow

**Step 1: Verify Image URL**

Ensure the reference image is:
- Publicly accessible URL
