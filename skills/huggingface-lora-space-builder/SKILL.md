---
name: huggingface-lora-space-builder
description: Build and publish a Gradio demo on Hugging Face Spaces for a user-provided LoRA. Use when someone asks to create, generate, ship, or publish a Space, demo, Gradio app, or playground for a LoRA — inc
category: Document Processing
source: antigravity
tags: [python, react, api, ai, workflow, template, design, document, image, security]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/huggingface-lora-space-builder
---


# Gradio LoRA Space Builder
## When to Use

Use this skill when you need build and publish a Gradio demo on Hugging Face Spaces for a user-provided LoRA. Use when someone asks to create, generate, ship, or publish a Space, demo, Gradio app, or playground for a LoRA — including LoRAs for Qwen-Image, Qwen-Image-Edit, LTX-Video, Wan, FLUX, SDXL, or other...


Build and publish a Gradio demo on Hugging Face Spaces that runs inference with a user-provided LoRA. Use whenever someone asks to create, generate, ship, or publish "a Space", "a demo", "a Gradio app", or "a playground" for a LoRA — whether the base model is Qwen-Image, Qwen-Image-Edit, LTX, or another diffusion model. Also use when someone describes a LoRA they trained or hosts on the Hub and wants to share it. The default target is ZeroGPU hardware and the default inference library is `diffusers` when the base model supports it.

The output is a real, published Space (private by default) that the user can try in the browser, not a local script.

## What "good" looks like for these demos

The demo should feel handcrafted for this specific LoRA, not a generic template with the LoRA bolted on. Two LoRAs that share a task can still need different demos: a pose-control video LoRA and an outpainting video LoRA both take video in and produce video out, but the inputs the user provides, the preprocessing, and the controls are completely different. Recognizing that is the central job here.

Concretely, a good demo:

- Loads fast and runs fast — minimal model loading, sensible step count, no wasted computation per call.
- Has a UI with exactly the controls this LoRA needs and nothing else. Excess sliders are a cost, not a feature.
- Shows the user what's happening — progress, intermediate outputs where useful, the seed used, a clear error when input is missing.
- Honors the LoRA's own recommendations from its model card: trigger words, recommended step count, recommended guidance scale, recommended LoRA scale, example inputs.
- Is creative where creativity helps — interactive canvases, before/after sliders, side-by-side previews of intermediate processing — and plain where plainness is right.

## Workflow

Work through these phases in order. Information gathered in one phase decides the next.

1. Gather the LoRA info needed to pick a pipeline and design a UI.
2. Pick the base pipeline and inference recipe.
3. Design the UI for this specific LoRA's task and inputs.
4. Write `app.py`, `requirements.txt`, and `README.md` together; show all three to the user for one batched approval.
5. Publish the Space (private).

Don't drip-feed questions across multiple turns. Batch them.

---

## Phase 1 — Gather LoRA info

Required: a LoRA repo on the Hub (e.g. `username/my-lora`).

**First, try to read the repo without a token.** If it succeeds, the repo is public — proceed. If it fails with 401/403, the repo is private/gated and you need an authenticated session to read it. **Don't immediately ask for a token.** Check first whether the user is already authenticated.

```python
from huggingface_hub import HfApi, get_token

cached_token = get_token()  # picks up HF_TOKEN env var or cached CLI login
if cached_token:
    try:
        info = HfApi().whoami(token=cached_token)
        username = info["name"]
        # info also has fine-grained token scope info if applicable
    except Exception:
        cached_token = None  # token exists but is invalid/expired
```

Then:

- If a valid cached token exists *and* it can read the repo, use it. No prompt needed.
- If no cached token, or the cached token can't read this private repo, ask the user for a token — once, with the explanation below.

When asking for a token (and only when you actually need to ask):

> I need a Hugging Face access token with **write** scope (to read the LoRA if it's private/gated, and to publish the Space). Create one at https://huggingface.co/settings/tokens. Paste it here.

The same token will be reused for publishing in the final phase, so this is a one-time ask.

**Then read what's in the repo:**

- List the repo files (`huggingface_hub.HfApi().list_repo_files(repo_id)`). Look for `.safetensors`, `README.md`, example images/videos, multiple checkpoints.
- Fetch the model card (`huggingface_hub.ModelCard.load(repo_id)`). The `data` dict has structured fields; the `text` has the README body.
- If multiple `.safetensors` files exist, pick the right one — see "Picking the LoRA weights file" in `references/zerogpu-and-publishing.md`. Briefly: README-recommended file wins, then `pytorch_lora_weights.safetensors`, then latest training checkpoint, otherwise ask.

**From the model card, try to determine:**

- **Base model** — the `base_model` field, or text mentions in the README. Usually present. Use it to pick the pipeline reference file (see Phase 2).
- **Task** — `pipeline_tag` if set, otherwise inferred from the base model and README text. The five tasks this skill handles: `text-to-image`, `image-to-image`
