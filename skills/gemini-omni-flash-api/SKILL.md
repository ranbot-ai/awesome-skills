---
name: gemini-omni-flash-api
description: Use this skill for generative video editing, text-to-video, image-referenced video generation, and first-frame-to-video transition animations using the official google-genai SDK. Includes workflows fo
category: Document Processing
source: antigravity
tags: [python, api, ai, workflow, design, document, image, security, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/gemini-omni-flash-api
---


# Gemini Omni Flash Skill
## When to Use

Use this skill when you need use this skill for generative video editing, text-to-video, image-referenced video generation, and first-frame-to-video transition animations using the official google-genai SDK. Includes workflows for pre-processing/optimizing high-resolution or long source videos with ffmpeg,...


This skill uses the Gemini Omni Flash model (`gemini-omni-flash-preview`) to perform text to video generation, image to video generation and video editing.

> [!WARNING]
> **Important Regional Restrictions**: Uploading videos to use for video edits is **NOT** available in the EEA, Switzerland, the United Kingdom, and some US states. If a video-to-video edit completes quickly with empty outputs (`total_output_tokens: 0` or no video content), it is likely due to this restriction.

## Core capabilities

1. **Video editing and refinement**: Editing existing videos (maximum duration 10 seconds), applying stylistic changes, or performing inpainting/outpainting.
2. **Text to video**: Generating videos from a text prompt.
3. **First-frame to video**: Generating videos from a single input image.
4. **Image-referenced generation**: Using style, character, or object references from images to guide video generation.

## Workflow

1. **Analyze request**: Determine the target task (e.g., first-frame-to-video, reference-guided editing) and identify any input media assets.
2. **Run SDK scripts**:

   * Directly run the appropriate utility (`scripts/video/generate_video.py` or `scripts/upload_file.py`).
   * Configure settings like `--aspect-ratio` (e.g. `16:9`, `9:16`) and `--duration` (any integer between `3` and `10` seconds, e.g. `3`, `5`, `10`).

3. **Retrieve and process output**: Outputs are saved to the local filesystem (e.g. `media/`). Report back the completed media path to the user.

## Reference Documentation

* **Interactions API**: All operations and state management for the Gemini Omni Flash model (`gemini-omni-flash-preview`) are handled via the [Interactions API](https://ai.google.dev/gemini-api/docs/interactions-overview).
* **Files API**: Input media files (such as reference images and videos) must be uploaded via the [Files API](https://ai.google.dev/gemini-api/docs/interactions/files) first before being referenced in generations. The uploaded file URI and MIME type are then included in the `interactions.create` input parts array.
* **[Interactions API Skill Reference](https://github.com/google-gemini/gemini-skills/blob/main/skills/gemini-interactions-api/SKILL.md)**: Platform-wide guidelines, current model specifications, and SDK usage rules for the Interactions API.

## Dependencies and Prerequisites

* **Python SDK (`google-genai`)**: Requires `google-genai >= 2.10.0` (Python) to support the new `interactions` client attribute. Install or upgrade using:
  ```bash
  pip install -U google-genai
  ```
* **Python Runtime**: Requires **Python >= 3.10** (for compatibility with modern `google-genai` SDK types and methods).
* **ffmpeg & ffprobe**: `prep_video.py`, `inspect_video.py`, and `generate_video.py` (when stripping audio via `--strip-audio`) require `ffmpeg` and `ffprobe` binaries installed and available in your system `PATH`.

## Available scripts

Use the following Python scripts to upload media with the Files API, prepare input videos with ffmpeg, and generate video outputs using the Interactions API.

1. **[upload_file.py](scripts/upload_file.py)**: Uploads local media (images and videos) to the Files API and polls until `ACTIVE`. If uploading a video larger than 25MB, it prints an informative warning/tip highlighting that Gemini Omni Flash is optimized for editing 10s videos at 720p/24fps, and recommends pre-processing with `prep_video.py` first to speed up the upload.

   ```bash
   ./scripts/upload_file.py path/to/image.png
   ```

2. **[generate_video.py](scripts/video/generate_video.py)**: Performs end-to-end video generation and downloads the output video. It detects and uploads local media references (images or videos) before calling the Interactions API. Large video assets (>25MB) will trigger informative pre-processing recommendations without blocking the upload.

   * **Text to video**:

     ```bash
     ./scripts/video/generate_video.py "A close-up of a cat drinking tea" --output media/cat_tea.mp4
     ```

   * **Image to video (first frame and reference)**:

     ```bash
     ./scripts/video/generate_video.py "The waves crash against the shore." --image reference.png --output media/waves.mp4
     ```

   * **Video interpolation**:

     Provide exactly two images as keyframes to generate a transition video between them:

     ```bash
     ./scripts/video/generate_video.py "A smooth timelapse from sunrise to sunset" --image start.png --image end.png --output media/interpolation.mp4
     ```

   * **Video editing (keep original audio)**:

     ```bash
     ./scripts/video/generate_video.py "Transform the style to Japanese anime" --video
