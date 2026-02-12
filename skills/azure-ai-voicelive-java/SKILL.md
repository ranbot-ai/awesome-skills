---
name: azure-ai-voicelive-java
description: Azure AI VoiceLive SDK for Java. Real-time bidirectional voice conversations with AI assistants using WebSocket. Triggers: "VoiceLiveClient java", "voice assistant java", "real-time voice java", "audi
category: AI & Agents
source: antigravity
tags: [react, api, ai, gpt, workflow, azure]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/azure-ai-voicelive-java
---


# Azure AI VoiceLive SDK for Java

Real-time, bidirectional voice conversations with AI assistants using WebSocket technology.

## Installation

```xml
<dependency>
    <groupId>com.azure</groupId>
    <artifactId>azure-ai-voicelive</artifactId>
    <version>1.0.0-beta.2</version>
</dependency>
```

## Environment Variables

```bash
AZURE_VOICELIVE_ENDPOINT=https://<resource>.openai.azure.com/
AZURE_VOICELIVE_API_KEY=<your-api-key>
```

## Authentication

### API Key

```java
import com.azure.ai.voicelive.VoiceLiveAsyncClient;
import com.azure.ai.voicelive.VoiceLiveClientBuilder;
import com.azure.core.credential.AzureKeyCredential;

VoiceLiveAsyncClient client = new VoiceLiveClientBuilder()
    .endpoint(System.getenv("AZURE_VOICELIVE_ENDPOINT"))
    .credential(new AzureKeyCredential(System.getenv("AZURE_VOICELIVE_API_KEY")))
    .buildAsyncClient();
```

### DefaultAzureCredential (Recommended)

```java
import com.azure.identity.DefaultAzureCredentialBuilder;

VoiceLiveAsyncClient client = new VoiceLiveClientBuilder()
    .endpoint(System.getenv("AZURE_VOICELIVE_ENDPOINT"))
    .credential(new DefaultAzureCredentialBuilder().build())
    .buildAsyncClient();
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| `VoiceLiveAsyncClient` | Main entry point for voice sessions |
| `VoiceLiveSessionAsyncClient` | Active WebSocket connection for streaming |
| `VoiceLiveSessionOptions` | Configuration for session behavior |

### Audio Requirements

- **Sample Rate**: 24kHz (24000 Hz)
- **Bit Depth**: 16-bit PCM
- **Channels**: Mono (1 channel)
- **Format**: Signed PCM, little-endian

## Core Workflow

### 1. Start Session

```java
import reactor.core.publisher.Mono;

client.startSession("gpt-4o-realtime-preview")
    .flatMap(session -> {
        System.out.println("Session started");
        
        // Subscribe to events
        session.receiveEvents()
            .subscribe(
                event -> System.out.println("Event: " + event.getType()),
                error -> System.err.println("Error: " + error.getMessage())
            );
        
        return Mono.just(session);
    })
    .block();
```

### 2. Configure Session Options

```java
import com.azure.ai.voicelive.models.*;
import java.util.Arrays;

ServerVadTurnDetection turnDetection = new ServerVadTurnDetection()
    .setThreshold(0.5)                    // Sensitivity (0.0-1.0)
    .setPrefixPaddingMs(300)              // Audio before speech
    .setSilenceDurationMs(500)            // Silence to end turn
    .setInterruptResponse(true)           // Allow interruptions
    .setAutoTruncate(true)
    .setCreateResponse(true);

AudioInputTranscriptionOptions transcription = new AudioInputTranscriptionOptions(
    AudioInputTranscriptionOptionsModel.WHISPER_1);

VoiceLiveSessionOptions options = new VoiceLiveSessionOptions()
    .setInstructions("You are a helpful AI voice assistant.")
    .setVoice(BinaryData.fromObject(new OpenAIVoice(OpenAIVoiceName.ALLOY)))
    .setModalities(Arrays.asList(InteractionModality.TEXT, InteractionModality.AUDIO))
    .setInputAudioFormat(InputAudioFormat.PCM16)
    .setOutputAudioFormat(OutputAudioFormat.PCM16)
    .setInputAudioSamplingRate(24000)
    .setInputAudioNoiseReduction(new AudioNoiseReduction(AudioNoiseReductionType.NEAR_FIELD))
    .setInputAudioEchoCancellation(new AudioEchoCancellation())
    .setInputAudioTranscription(transcription)
    .setTurnDetection(turnDetection);

// Send configuration
ClientEventSessionUpdate updateEvent = new ClientEventSessionUpdate(options);
session.sendEvent(updateEvent).subscribe();
```

### 3. Send Audio Input

```java
byte[] audioData = readAudioChunk(); // Your PCM16 audio data
session.sendInputAudio(BinaryData.fromBytes(audioData)).subscribe();
```

### 4. Handle Events

```java
session.receiveEvents().subscribe(event -> {
    ServerEventType eventType = event.getType();
    
    if (ServerEventType.SESSION_CREATED.equals(eventType)) {
        System.out.println("Session created");
    } else if (ServerEventType.INPUT_AUDIO_BUFFER_SPEECH_STARTED.equals(eventType)) {
        System.out.println("User started speaking");
    } else if (ServerEventType.INPUT_AUDIO_BUFFER_SPEECH_STOPPED.equals(eventType)) {
        System.out.println("User stopped speaking");
    } else if (ServerEventType.RESPONSE_AUDIO_DELTA.equals(eventType)) {
        if (event instanceof SessionUpdateResponseAudioDelta) {
            SessionUpdateResponseAudioDelta audioEvent = (SessionUpdateResponseAudioDelta) event;
            playAudioChunk(audioEvent.getDelta());
        }
    } else if (ServerEventType.RESPONSE_DONE.equals(eventType)) {
        System.out.println("Response complete");
    } else if (ServerEventType.ERROR.equals(eventType)) {
        if (event instanceof SessionUpdateError) {
            SessionUpdateError errorEvent = (SessionUpdateError) event;
            System.err.println("Error: " + errorEvent.getError().getMessage());
        }
    }
});
```

## 
