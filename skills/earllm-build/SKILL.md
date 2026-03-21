---
name: earllm-build
description: Build, maintain, and extend the EarLLM One Android project — a Kotlin/Compose app that connects Bluetooth earbuds to an LLM via voice pipeline. 
category: AI & Agents
source: antigravity
tags: [api, claude, ai, llm, document, security, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/earllm-build
---


# EarLLM One — Build & Maintain

## Overview

Build, maintain, and extend the EarLLM One Android project — a Kotlin/Compose app that connects Bluetooth earbuds to an LLM via voice pipeline.

## When to Use This Skill

- When the user mentions "earllm" or related topics
- When the user mentions "earbudllm" or related topics
- When the user mentions "earbud app" or related topics
- When the user mentions "voice pipeline kotlin" or related topics
- When the user mentions "bluetooth audio android" or related topics
- When the user mentions "sco microphone" or related topics

## Do Not Use This Skill When

- The task is unrelated to earllm build
- A simpler, more specific tool can handle the request
- The user needs general-purpose assistance without domain expertise

## How It Works

EarLLM One is a multi-module Android app (Kotlin + Jetpack Compose) that captures voice from Bluetooth earbuds, transcribes it, sends it to an LLM, and speaks the response back.

## Project Location

`C:\Users\renat\earbudllm`

## Module Dependency Graph

```
app ──→ voice ──→ audio ──→ core-logging
  │       │
  ├──→ bluetooth ──→ core-logging
  └──→ llm ──→ core-logging
```

## Modules And Key Files

| Module | Purpose | Key Files |
|--------|---------|-----------|
| **core-logging** | Structured logging, performance tracking | `EarLogger.kt`, `PerformanceTracker.kt` |
| **bluetooth** | BT discovery, pairing, A2DP/HFP profiles | `BluetoothController.kt`, `BluetoothState.kt`, `BluetoothPermissions.kt` |
| **audio** | Audio routing (SCO/BLE), capture, headset buttons | `AudioRouteController.kt`, `VoiceCaptureController.kt`, `HeadsetButtonController.kt` |
| **voice** | STT (SpeechRecognizer + Vosk stub), TTS, pipeline | `SpeechToTextController.kt`, `TextToSpeechController.kt`, `VoicePipeline.kt` |
| **llm** | LLM interface, stub, OpenAI-compatible client | `LlmClient.kt`, `StubLlmClient.kt`, `RealLlmClient.kt`, `SecureTokenStore.kt` |
| **app** | UI, ViewModel, Service, Settings, all screens | `MainViewModel.kt`, `EarLlmForegroundService.kt`, 6 Compose screens |

## Build Configuration

- **SDK**: minSdk 26, targetSdk 34, compileSdk 34
- **Build tools**: AGP 8.2.2, Kotlin 1.9.22, Gradle 8.5
- **Compose BOM**: 2024.02.00
- **Key deps**: OkHttp, AndroidX Security (EncryptedSharedPreferences), DataStore, Media

## Target Hardware

| Device | Model | Key Details |
|--------|-------|-------------|
| Phone | Samsung Galaxy S24 Ultra | Android 14, One UI 6.1, Snapdragon 8 Gen 3 |
| Earbuds | Xiaomi Redmi Buds 6 Pro | BT 5.3, A2DP/HFP/AVRCP, ANC, LDAC |

## Critical Technical Facts

These are verified facts from official documentation and device testing. Treat them as ground truth when making decisions:

1. **Bluetooth SCO is limited to 8kHz mono input** on most devices. Some support 16kHz mSBC. BLE Audio (Android 12+, `TYPE_BLE_HEADSET = 26`) supports up to 32kHz stereo. Always prefer BLE Audio when available.

2. **`startBluetoothSco()` is deprecated since Android 12 (API 31).** Use `AudioManager.setCommunicationDevice(AudioDeviceInfo)` and `clearCommunicationDevice()` instead. The project already implements both paths in `AudioRouteController.kt`.

3. **Samsung One UI 7/8 has a known HFP corruption bug** where A2DP playback corrupts the SCO link. The app handles this with silence detection and automatic fallback to the phone's built-in mic.

4. **Redmi Buds 6 Pro tap controls must be set to "Default" (Play/Pause)** in the Xiaomi Earbuds companion app. If set to ANC or custom functions, events are handled internally by the earbuds and never reach Android.

5. **Android 14+ requires `FOREGROUND_SERVICE_MICROPHONE` permission** and `foregroundServiceType="microphone"` in the service declaration. `RECORD_AUDIO` must be granted before `startForeground()`.

6. **`VOICE_COMMUNICATION` audio source enables AEC** (Acoustic Echo Cancellation), which is critical to prevent TTS audio output from feeding back into the STT microphone input. Never change this source without understanding the echo implications.

7. **Never play TTS (A2DP) while simultaneously recording via SCO.** The correct sequence is: stop playback → switch to HFP → record → switch to A2DP → play response.

## Data Flow

```
Headset button tap
  → MediaSession (HeadsetButtonController)
  → TapAction.RECORD_TOGGLE
  → VoicePipeline.toggleRecording()
  → VoiceCaptureController captures PCM (16kHz mono)
  → stopRecording() returns ByteArray
  → SpeechToTextController.transcribe(pcmData)
  → LlmClient.chat(messages)
  → TextToSpeechController.speak(response)
  → Audio output via A2DP to earbuds
```

## Adding A New Feature

1. Identify which module(s) are affected
2. Read existing code in those modules first
3. Follow the StateFlow pattern — expose state via `MutableStateFlow` / `StateFlow`
4. Update `MainViewModel.kt` if the feature needs UI integration
5. Add unit tests in the module's `src/test/` directory
6. Update docs if the feature changes behavior

## Modifying Audio Capture

- 
