---
name: azure-communication-callautomation-java
description: Build call automation workflows with Azure Communication Services Call Automation Java SDK. Use when implementing IVR systems, call routing, call recording, DTMF recognition, text-to-speech, or AI-pow
category: AI & Agents
source: antigravity
tags: [api, ai, llm, automation, workflow, azure, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/azure-communication-callautomation-java
---


# Azure Communication Call Automation (Java)

Build server-side call automation workflows including IVR systems, call routing, recording, and AI-powered interactions.

## Installation

```xml
<dependency>
    <groupId>com.azure</groupId>
    <artifactId>azure-communication-callautomation</artifactId>
    <version>1.6.0</version>
</dependency>
```

## Client Creation

```java
import com.azure.communication.callautomation.CallAutomationClient;
import com.azure.communication.callautomation.CallAutomationClientBuilder;
import com.azure.identity.DefaultAzureCredentialBuilder;

// With DefaultAzureCredential
CallAutomationClient client = new CallAutomationClientBuilder()
    .endpoint("https://<resource>.communication.azure.com")
    .credential(new DefaultAzureCredentialBuilder().build())
    .buildClient();

// With connection string
CallAutomationClient client = new CallAutomationClientBuilder()
    .connectionString("<connection-string>")
    .buildClient();
```

## Key Concepts

| Class | Purpose |
|-------|---------|
| `CallAutomationClient` | Make calls, answer/reject incoming calls, redirect calls |
| `CallConnection` | Actions in established calls (add participants, terminate) |
| `CallMedia` | Media operations (play audio, recognize DTMF/speech) |
| `CallRecording` | Start/stop/pause recording |
| `CallAutomationEventParser` | Parse webhook events from ACS |

## Create Outbound Call

```java
import com.azure.communication.callautomation.models.*;
import com.azure.communication.common.CommunicationUserIdentifier;
import com.azure.communication.common.PhoneNumberIdentifier;

// Call to PSTN number
PhoneNumberIdentifier target = new PhoneNumberIdentifier("+14255551234");
PhoneNumberIdentifier caller = new PhoneNumberIdentifier("+14255550100");

CreateCallOptions options = new CreateCallOptions(
    new CommunicationUserIdentifier("<user-id>"),  // Source
    List.of(target))                                // Targets
    .setSourceCallerId(caller)
    .setCallbackUrl("https://your-app.com/api/callbacks");

CreateCallResult result = client.createCall(options);
String callConnectionId = result.getCallConnectionProperties().getCallConnectionId();
```

## Answer Incoming Call

```java
// From Event Grid webhook - IncomingCall event
String incomingCallContext = "<incoming-call-context-from-event>";

AnswerCallOptions options = new AnswerCallOptions(
    incomingCallContext,
    "https://your-app.com/api/callbacks");

AnswerCallResult result = client.answerCall(options);
CallConnection callConnection = result.getCallConnection();
```

## Play Audio (Text-to-Speech)

```java
CallConnection callConnection = client.getCallConnection(callConnectionId);
CallMedia callMedia = callConnection.getCallMedia();

// Play text-to-speech
TextSource textSource = new TextSource()
    .setText("Welcome to Contoso. Press 1 for sales, 2 for support.")
    .setVoiceName("en-US-JennyNeural");

PlayOptions playOptions = new PlayOptions(
    List.of(textSource),
    List.of(new CommunicationUserIdentifier("<target-user>")));

callMedia.play(playOptions);

// Play audio file
FileSource fileSource = new FileSource()
    .setUrl("https://storage.blob.core.windows.net/audio/greeting.wav");

callMedia.play(new PlayOptions(List.of(fileSource), List.of(target)));
```

## Recognize DTMF Input

```java
// Recognize DTMF tones
DtmfTone stopTones = DtmfTone.POUND;

CallMediaRecognizeDtmfOptions recognizeOptions = new CallMediaRecognizeDtmfOptions(
    new CommunicationUserIdentifier("<target-user>"),
    5)  // Max tones to collect
    .setInterToneTimeout(Duration.ofSeconds(5))
    .setStopTones(List.of(stopTones))
    .setInitialSilenceTimeout(Duration.ofSeconds(15))
    .setPlayPrompt(new TextSource().setText("Enter your account number followed by pound."));

callMedia.startRecognizing(recognizeOptions);
```

## Recognize Speech

```java
// Speech recognition with AI
CallMediaRecognizeSpeechOptions speechOptions = new CallMediaRecognizeSpeechOptions(
    new CommunicationUserIdentifier("<target-user>"))
    .setEndSilenceTimeout(Duration.ofSeconds(2))
    .setSpeechLanguage("en-US")
    .setPlayPrompt(new TextSource().setText("How can I help you today?"));

callMedia.startRecognizing(speechOptions);
```

## Call Recording

```java
CallRecording callRecording = client.getCallRecording();

// Start recording
StartRecordingOptions recordingOptions = new StartRecordingOptions(
    new ServerCallLocator("<server-call-id>"))
    .setRecordingChannel(RecordingChannel.MIXED)
    .setRecordingContent(RecordingContent.AUDIO_VIDEO)
    .setRecordingFormat(RecordingFormat.MP4);

RecordingStateResult recordingResult = callRecording.start(recordingOptions);
String recordingId = recordingResult.getRecordingId();

// Pause/resume/stop
callRecording.pause(recordingId);
callRecording.resume(recordingId);
callRecording.stop(recordingId);

// Download recording (after RecordingFileStatusUpdated event)
callRecording.downloadTo(recordingUrl, Paths.get("recording.m
