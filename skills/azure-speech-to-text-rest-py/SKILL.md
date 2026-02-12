---
name: azure-speech-to-text-rest-py
description: Azure Speech to Text REST API for short audio (Python). Use for simple speech recognition of audio files up to 60 seconds without the Speech SDK. Triggers: "speech to text REST", "short audio transcri
category: AI & Agents
source: antigravity
tags: [python, api, ai, azure, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/azure-speech-to-text-rest-py
---


# Azure Speech to Text REST API for Short Audio

Simple REST API for speech-to-text transcription of short audio files (up to 60 seconds). No SDK required - just HTTP requests.

## Prerequisites

1. **Azure subscription** - [Create one free](https://azure.microsoft.com/free/)
2. **Speech resource** - Create in [Azure Portal](https://portal.azure.com/#create/Microsoft.CognitiveServicesSpeechServices)
3. **Get credentials** - After deployment, go to resource > Keys and Endpoint

## Environment Variables

```bash
# Required
AZURE_SPEECH_KEY=<your-speech-resource-key>
AZURE_SPEECH_REGION=<region>  # e.g., eastus, westus2, westeurope

# Alternative: Use endpoint directly
AZURE_SPEECH_ENDPOINT=https://<region>.stt.speech.microsoft.com
```

## Installation

```bash
pip install requests
```

## Quick Start

```python
import os
import requests

def transcribe_audio(audio_file_path: str, language: str = "en-US") -> dict:
    """Transcribe short audio file (max 60 seconds) using REST API."""
    region = os.environ["AZURE_SPEECH_REGION"]
    api_key = os.environ["AZURE_SPEECH_KEY"]
    
    url = f"https://{region}.stt.speech.microsoft.com/speech/recognition/conversation/cognitiveservices/v1"
    
    headers = {
        "Ocp-Apim-Subscription-Key": api_key,
        "Content-Type": "audio/wav; codecs=audio/pcm; samplerate=16000",
        "Accept": "application/json"
    }
    
    params = {
        "language": language,
        "format": "detailed"  # or "simple"
    }
    
    with open(audio_file_path, "rb") as audio_file:
        response = requests.post(url, headers=headers, params=params, data=audio_file)
    
    response.raise_for_status()
    return response.json()

# Usage
result = transcribe_audio("audio.wav", "en-US")
print(result["DisplayText"])
```

## Audio Requirements

| Format | Codec | Sample Rate | Notes |
|--------|-------|-------------|-------|
| WAV | PCM | 16 kHz, mono | **Recommended** |
| OGG | OPUS | 16 kHz, mono | Smaller file size |

**Limitations:**
- Maximum 60 seconds of audio
- For pronunciation assessment: maximum 30 seconds
- No partial/interim results (final only)

## Content-Type Headers

```python
# WAV PCM 16kHz
"Content-Type": "audio/wav; codecs=audio/pcm; samplerate=16000"

# OGG OPUS
"Content-Type": "audio/ogg; codecs=opus"
```

## Response Formats

### Simple Format (default)

```python
params = {"language": "en-US", "format": "simple"}
```

```json
{
  "RecognitionStatus": "Success",
  "DisplayText": "Remind me to buy 5 pencils.",
  "Offset": "1236645672289",
  "Duration": "1236645672289"
}
```

### Detailed Format

```python
params = {"language": "en-US", "format": "detailed"}
```

```json
{
  "RecognitionStatus": "Success",
  "Offset": "1236645672289",
  "Duration": "1236645672289",
  "NBest": [
    {
      "Confidence": 0.9052885,
      "Display": "What's the weather like?",
      "ITN": "what's the weather like",
      "Lexical": "what's the weather like",
      "MaskedITN": "what's the weather like"
    }
  ]
}
```

## Chunked Transfer (Recommended)

For lower latency, stream audio in chunks:

```python
import os
import requests

def transcribe_chunked(audio_file_path: str, language: str = "en-US") -> dict:
    """Stream audio in chunks for lower latency."""
    region = os.environ["AZURE_SPEECH_REGION"]
    api_key = os.environ["AZURE_SPEECH_KEY"]
    
    url = f"https://{region}.stt.speech.microsoft.com/speech/recognition/conversation/cognitiveservices/v1"
    
    headers = {
        "Ocp-Apim-Subscription-Key": api_key,
        "Content-Type": "audio/wav; codecs=audio/pcm; samplerate=16000",
        "Accept": "application/json",
        "Transfer-Encoding": "chunked",
        "Expect": "100-continue"
    }
    
    params = {"language": language, "format": "detailed"}
    
    def generate_chunks(file_path: str, chunk_size: int = 1024):
        with open(file_path, "rb") as f:
            while chunk := f.read(chunk_size):
                yield chunk
    
    response = requests.post(
        url, 
        headers=headers, 
        params=params, 
        data=generate_chunks(audio_file_path)
    )
    
    response.raise_for_status()
    return response.json()
```

## Authentication Options

### Option 1: Subscription Key (Simple)

```python
headers = {
    "Ocp-Apim-Subscription-Key": os.environ["AZURE_SPEECH_KEY"]
}
```

### Option 2: Bearer Token

```python
import requests
import os

def get_access_token() -> str:
    """Get access token from the token endpoint."""
    region = os.environ["AZURE_SPEECH_REGION"]
    api_key = os.environ["AZURE_SPEECH_KEY"]
    
    token_url = f"https://{region}.api.cognitive.microsoft.com/sts/v1.0/issueToken"
    
    response = requests.post(
        token_url,
        headers={
            "Ocp-Apim-Subscription-Key": api_key,
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": "0"
        }
    )
    response.raise_for_status()
    return response.text

# Use token in requests (val
