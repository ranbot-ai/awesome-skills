---
name: gemini-live-api-dev
description: Use this skill when building real-time, bidirectional streaming applications with the Gemini Live API. Covers WebSocket-based audio/video/text streaming, voice activity detection (VAD), native audio f
category: Document Processing
source: antigravity
tags: [python, javascript, typescript, api, mcp, ai, agent, llm, document, image]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/gemini-live-api-dev
---


# Gemini Live API Development Skill
## When to Use

Use this skill when building real-time, bidirectional streaming applications with the Gemini Live API. Covers WebSocket-based audio/video/text streaming, voice activity detection (VAD), native audio features, function calling, session management, ephemeral tokens for client-side auth,...


## Overview

The Live API enables **low-latency, real-time voice and video interactions** with Gemini over WebSockets. It processes continuous streams of audio, video, or text to deliver immediate, human-like spoken responses.

Key capabilities:
- **Bidirectional audio streaming** — real-time mic-to-speaker conversations
- **Video streaming** — send camera/screen frames alongside audio
- **Text input/output** — send and receive text within a live session
- **Audio transcriptions** — get text transcripts of both input and output audio
- **Voice Activity Detection (VAD)** — automatic interruption handling
- **Native audio** — thinking (with configurable `thinkingLevel`)
- **Function calling** — synchronous tool use
- **Google Search grounding** — ground responses in real-time search results
- **Session management** — context compression, session resumption, GoAway signals
- **Ephemeral tokens** — secure client-side authentication

> [!NOTE]
> The Live API currently **only supports WebSockets**. For WebRTC support or simplified integration, use a [partner integration](#partner-integrations).

## Models

- `gemini-3.1-flash-live-preview` — Optimized for low-latency, real-time dialogue. Native audio output, thinking (via `thinkingLevel`). 128k context window. **This is the recommended model for all Live API use cases.**
- `gemini-3.5-live-translate-preview` — Real-time streaming translation model.

> [!WARNING]
> The following Live API models are **deprecated** and will be shut down. Migrate to `gemini-3.1-flash-live-preview`.
> - `gemini-2.5-flash-native-audio-preview-12-2025` — Migrate to `gemini-3.1-flash-live-preview`.
> - `gemini-live-2.5-flash-preview` — Released June 17, 2025. Shutdown: December 9, 2025.
> - `gemini-2.0-flash-live-001` — Released April 9, 2025. Shutdown: December 9, 2025.

## SDKs

- **Python**: `google-genai` — `pip install google-genai`
- **JavaScript/TypeScript**: `@google/genai` — `npm install @google/genai`

> [!WARNING]
> Legacy SDKs `google-generativeai` (Python) and `@google/generative-ai` (JS) are deprecated. Use the new SDKs above.

## Partner Integrations

To streamline real-time audio/video app development, use a third-party integration supporting the Gemini Live API over **WebRTC** or **WebSockets**:

- [LiveKit](https://docs.livekit.io/agents/models/realtime/plugins/gemini/) — Use the Gemini Live API with LiveKit Agents.
- [Pipecat by Daily](https://docs.pipecat.ai/guides/features/gemini-live) — Create a real-time AI chatbot using Gemini Live and Pipecat.
- [Fishjam by Software Mansion](https://docs.fishjam.io/tutorials/gemini-live-integration) — Create live video and audio streaming applications with Fishjam.
- [Vision Agents by Stream](https://visionagents.ai/integrations/gemini) — Build real-time voice and video AI applications with Vision Agents.
- [Voximplant](https://voximplant.com/products/gemini-client) — Connect inbound and outbound calls to Live API with Voximplant.
- [Firebase AI SDK](https://firebase.google.com/docs/ai-logic/live-api?api=dev) — Get started with the Gemini Live API using Firebase AI Logic.

## Audio Formats

- **Input**: Raw PCM, little-endian, 16-bit, mono. 16kHz native (will resample others). MIME type: `audio/pcm;rate=16000`
- **Output**: Raw PCM, little-endian, 16-bit, mono. 24kHz sample rate.

> [!IMPORTANT]
> Use `send_realtime_input` / `sendRealtimeInput` for all real-time user input (audio, video, **and text**). `send_client_content` / `sendClientContent` is **only** supported for seeding initial context history (requires setting `initial_history_in_client_content` in `history_config`). Do **not** use it to send new user messages during the conversation.

> [!WARNING]
> Do **not** use `media` in `sendRealtimeInput`. Use the specific keys: `audio` for audio data, `video` for images/video frames, and `text` for text input.

---

## Quick Start

### Authentication

#### Python

```python
import os
from google import genai

client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
```

#### JavaScript

```js
import { GoogleGenAI } from '@google/genai';

const ai = new GoogleGenAI({ apiKey: 'YOUR_API_KEY' });
```

### Connecting to the Live API

#### Python
```python
from google.genai import types

config = types.LiveConnectConfig(
    response_modalities=[types.Modality.AUDIO],
    system_instruction=types.Content(
        parts=[types.Part(text="You are a helpful assistant.")]
    )
)

async with client.aio.live.connect(model="gemini-3.1-flash-live-preview", config=config) as session:
    pass  # Session is active
```

#### JavaScript
```js
const session = await ai.live.connect({
  model: 'gemini-3.1-fl
