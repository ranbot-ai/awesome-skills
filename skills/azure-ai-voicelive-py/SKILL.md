---
name: azure-ai-voicelive-py
description: Build real-time voice AI applications using Azure AI Voice Live SDK (azure-ai-voicelive). Use this skill when creating Python applications that need real-time bidirectional audio communication with Az
category: AI & Agents
source: antigravity
tags: [python, api, mcp, ai, gpt, azure, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/azure-ai-voicelive-py
---


# Azure AI Voice Live SDK

Build real-time voice AI applications with bidirectional WebSocket communication.

## Installation

```bash
pip install azure-ai-voicelive aiohttp azure-identity
```

## Environment Variables

```bash
AZURE_COGNITIVE_SERVICES_ENDPOINT=https://<region>.api.cognitive.microsoft.com
# For API key auth (not recommended for production)
AZURE_COGNITIVE_SERVICES_KEY=<api-key>
```

## Authentication

**DefaultAzureCredential (preferred)**:
```python
from azure.ai.voicelive.aio import connect
from azure.identity.aio import DefaultAzureCredential

async with connect(
    endpoint=os.environ["AZURE_COGNITIVE_SERVICES_ENDPOINT"],
    credential=DefaultAzureCredential(),
    model="gpt-4o-realtime-preview",
    credential_scopes=["https://cognitiveservices.azure.com/.default"]
) as conn:
    ...
```

**API Key**:
```python
from azure.ai.voicelive.aio import connect
from azure.core.credentials import AzureKeyCredential

async with connect(
    endpoint=os.environ["AZURE_COGNITIVE_SERVICES_ENDPOINT"],
    credential=AzureKeyCredential(os.environ["AZURE_COGNITIVE_SERVICES_KEY"]),
    model="gpt-4o-realtime-preview"
) as conn:
    ...
```

## Quick Start

```python
import asyncio
import os
from azure.ai.voicelive.aio import connect
from azure.identity.aio import DefaultAzureCredential

async def main():
    async with connect(
        endpoint=os.environ["AZURE_COGNITIVE_SERVICES_ENDPOINT"],
        credential=DefaultAzureCredential(),
        model="gpt-4o-realtime-preview",
        credential_scopes=["https://cognitiveservices.azure.com/.default"]
    ) as conn:
        # Update session with instructions
        await conn.session.update(session={
            "instructions": "You are a helpful assistant.",
            "modalities": ["text", "audio"],
            "voice": "alloy"
        })
        
        # Listen for events
        async for event in conn:
            print(f"Event: {event.type}")
            if event.type == "response.audio_transcript.done":
                print(f"Transcript: {event.transcript}")
            elif event.type == "response.done":
                break

asyncio.run(main())
```

## Core Architecture

### Connection Resources

The `VoiceLiveConnection` exposes these resources:

| Resource | Purpose | Key Methods |
|----------|---------|-------------|
| `conn.session` | Session configuration | `update(session=...)` |
| `conn.response` | Model responses | `create()`, `cancel()` |
| `conn.input_audio_buffer` | Audio input | `append()`, `commit()`, `clear()` |
| `conn.output_audio_buffer` | Audio output | `clear()` |
| `conn.conversation` | Conversation state | `item.create()`, `item.delete()`, `item.truncate()` |
| `conn.transcription_session` | Transcription config | `update(session=...)` |

## Session Configuration

```python
from azure.ai.voicelive.models import RequestSession, FunctionTool

await conn.session.update(session=RequestSession(
    instructions="You are a helpful voice assistant.",
    modalities=["text", "audio"],
    voice="alloy",  # or "echo", "shimmer", "sage", etc.
    input_audio_format="pcm16",
    output_audio_format="pcm16",
    turn_detection={
        "type": "server_vad",
        "threshold": 0.5,
        "prefix_padding_ms": 300,
        "silence_duration_ms": 500
    },
    tools=[
        FunctionTool(
            type="function",
            name="get_weather",
            description="Get current weather",
            parameters={
                "type": "object",
                "properties": {
                    "location": {"type": "string"}
                },
                "required": ["location"]
            }
        )
    ]
))
```

## Audio Streaming

### Send Audio (Base64 PCM16)

```python
import base64

# Read audio chunk (16-bit PCM, 24kHz mono)
audio_chunk = await read_audio_from_microphone()
b64_audio = base64.b64encode(audio_chunk).decode()

await conn.input_audio_buffer.append(audio=b64_audio)
```

### Receive Audio

```python
async for event in conn:
    if event.type == "response.audio.delta":
        audio_bytes = base64.b64decode(event.delta)
        await play_audio(audio_bytes)
    elif event.type == "response.audio.done":
        print("Audio complete")
```

## Event Handling

```python
async for event in conn:
    match event.type:
        # Session events
        case "session.created":
            print(f"Session: {event.session}")
        case "session.updated":
            print("Session updated")
        
        # Audio input events
        case "input_audio_buffer.speech_started":
            print(f"Speech started at {event.audio_start_ms}ms")
        case "input_audio_buffer.speech_stopped":
            print(f"Speech stopped at {event.audio_end_ms}ms")
        
        # Transcription events
        case "conversation.item.input_audio_transcription.completed":
            print(f"User said: {event.transcript}")
        case "conversation.item.input_audio_transcription.delta":
            print(f"Pa
