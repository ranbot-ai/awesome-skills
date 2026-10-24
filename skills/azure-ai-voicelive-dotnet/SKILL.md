---
name: azure-ai-voicelive-dotnet
description: Azure AI Voice Live SDK for .NET. Build real-time voice AI applications with bidirectional WebSocket communication. 
category: Document Processing
source: antigravity
tags: [api, ai, gpt, workflow, document, azure, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/azure-ai-voicelive-dotnet
---


# Azure.AI.VoiceLive (.NET)

Real-time voice AI SDK for building bidirectional voice assistants with Azure AI.

## Installation

```bash
dotnet add package Azure.AI.VoiceLive
dotnet add package Azure.Identity
dotnet add package NAudio                    # For audio capture/playback
```

**Version scope**: Examples are SDK fragments; pin a compatible package and check its API/model availability in the linked Microsoft documentation rather than treating these examples as a current version list.

## Environment Variables

```bash
AZURE_VOICELIVE_ENDPOINT=https://<resource>.services.ai.azure.com/
AZURE_VOICELIVE_MODEL=gpt-4o-realtime-preview
AZURE_VOICELIVE_VOICE=en-US-AvaNeural
# Optional: API key if not using Entra ID
AZURE_VOICELIVE_API_KEY=<your-api-key>
```

## Authentication

### Microsoft Entra ID (Recommended)

```csharp
using Azure.Identity;
using Azure.AI.VoiceLive;

Uri endpoint = new Uri("https://your-resource.cognitiveservices.azure.com");
DefaultAzureCredential credential = new DefaultAzureCredential();
VoiceLiveClient client = new VoiceLiveClient(endpoint, credential);
```

**Required Role**: `Cognitive Services User` (assign in Azure Portal → Access control)

### API Key

```csharp
Uri endpoint = new Uri("https://your-resource.cognitiveservices.azure.com");
AzureKeyCredential credential = new AzureKeyCredential("your-api-key");
VoiceLiveClient client = new VoiceLiveClient(endpoint, credential);
```

## Client Hierarchy

```
VoiceLiveClient
└── VoiceLiveSession (WebSocket connection)
    ├── ConfigureSessionAsync()
    ├── GetUpdatesAsync() → SessionUpdate events
    ├── AddItemAsync() → UserMessageItem, FunctionCallOutputItem
    ├── SendAudioAsync()
    └── StartResponseAsync()
```

## Voice and tool boundaries

Obtain applicable microphone/recording/transmission consent, select an approved Azure resource/region and bound session duration/costs. Model-provided tool arguments are untrusted: validate schema, allowlist operations, and require authorization for external effects. Do not place secrets in instructions/logs or treat a function definition as an executed integration. Reconfigure the session after adding tools; exact audio formats/rates depend on the pinned model and SDK.

## Core Workflow

### 1. Start Session and Configure

```csharp
using Azure.Identity;
using Azure.AI.VoiceLive;

var endpoint = new Uri(Environment.GetEnvironmentVariable("AZURE_VOICELIVE_ENDPOINT"));
var client = new VoiceLiveClient(endpoint, new DefaultAzureCredential());

var model = "gpt-4o-mini-realtime-preview";

// Start session
using VoiceLiveSession session = await client.StartSessionAsync(model);

// Configure session
VoiceLiveSessionOptions sessionOptions = new()
{
    Model = model,
    Instructions = "You are a helpful AI assistant. Respond naturally.",
    Voice = new AzureStandardVoice("en-US-AvaNeural"),
    TurnDetection = new AzureSemanticVadTurnDetection()
    {
        Threshold = 0.5f,
        PrefixPadding = TimeSpan.FromMilliseconds(300),
        SilenceDuration = TimeSpan.FromMilliseconds(500)
    },
    InputAudioFormat = InputAudioFormat.Pcm16,
    OutputAudioFormat = OutputAudioFormat.Pcm16
};

// Set modalities (both text and audio for voice assistants)
sessionOptions.Modalities.Clear();
sessionOptions.Modalities.Add(InteractionModality.Text);
sessionOptions.Modalities.Add(InteractionModality.Audio);

await session.ConfigureSessionAsync(sessionOptions);
```

### 2. Process Events

```csharp
await foreach (SessionUpdate serverEvent in session.GetUpdatesAsync())
{
    switch (serverEvent)
    {
        case SessionUpdateResponseAudioDelta audioDelta:
            byte[] audioData = audioDelta.Delta.ToArray();
            // Play audio via NAudio or other audio library
            break;
            
        case SessionUpdateResponseTextDelta textDelta:
            Console.Write(textDelta.Delta);
            break;
            
        case SessionUpdateResponseFunctionCallArgumentsDone functionCall:
            // Handle function call (see Function Calling section)
            break;
            
        case SessionUpdateError error:
            Console.WriteLine($"Error: {error.Error.Message}");
            break;
            
        case SessionUpdateResponseDone:
            Console.WriteLine("\n--- Response complete ---");
            break;
    }
}
```

### 3. Send User Message

```csharp
await session.AddItemAsync(new UserMessageItem("Hello, can you help me?"));
await session.StartResponseAsync();
```

### 4. Function Calling

```csharp
// Define function
var weatherFunction = new VoiceLiveFunctionDefinition("get_current_weather")
{
    Description = "Get the current weather for a given location",
    Parameters = BinaryData.FromString("""
        {
            "type": "object",
            "properties": {
                "location": {
                    "type": "string",
                    "description": "The city and state or country"
                }
            },
            "r
