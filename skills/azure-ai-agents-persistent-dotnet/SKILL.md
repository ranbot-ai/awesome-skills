---
name: azure-ai-agents-persistent-dotnet
description: Azure AI Agents Persistent SDK for .NET. Low-level SDK for creating and managing AI agents with threads, messages, runs, and tools. Use for agent CRUD, conversation threads, streaming responses, funct
category: AI & Agents
source: antigravity
tags: [python, api, mcp, ai, agent, gpt, workflow, document, azure, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/azure-ai-agents-persistent-dotnet
---


# Azure.AI.Agents.Persistent (.NET)

Low-level SDK for creating and managing persistent AI agents with threads, messages, runs, and tools.

## Installation

```bash
dotnet add package Azure.AI.Agents.Persistent --prerelease
dotnet add package Azure.Identity
```

**Current Versions**: Stable v1.1.0, Preview v1.2.0-beta.8

## Environment Variables

```bash
PROJECT_ENDPOINT=https://<resource>.services.ai.azure.com/api/projects/<project>
MODEL_DEPLOYMENT_NAME=gpt-4o-mini
AZURE_BING_CONNECTION_ID=<bing-connection-resource-id>
AZURE_AI_SEARCH_CONNECTION_ID=<search-connection-resource-id>
```

## Authentication

```csharp
using Azure.AI.Agents.Persistent;
using Azure.Identity;

var projectEndpoint = Environment.GetEnvironmentVariable("PROJECT_ENDPOINT");
PersistentAgentsClient client = new(projectEndpoint, new DefaultAzureCredential());
```

## Client Hierarchy

```
PersistentAgentsClient
├── Administration  → Agent CRUD operations
├── Threads         → Thread management
├── Messages        → Message operations
├── Runs            → Run execution and streaming
├── Files           → File upload/download
└── VectorStores    → Vector store management
```

## Core Workflow

### 1. Create Agent

```csharp
var modelDeploymentName = Environment.GetEnvironmentVariable("MODEL_DEPLOYMENT_NAME");

PersistentAgent agent = await client.Administration.CreateAgentAsync(
    model: modelDeploymentName,
    name: "Math Tutor",
    instructions: "You are a personal math tutor. Write and run code to answer math questions.",
    tools: [new CodeInterpreterToolDefinition()]
);
```

### 2. Create Thread and Message

```csharp
// Create thread
PersistentAgentThread thread = await client.Threads.CreateThreadAsync();

// Create message
await client.Messages.CreateMessageAsync(
    thread.Id,
    MessageRole.User,
    "I need to solve the equation `3x + 11 = 14`. Can you help me?"
);
```

### 3. Run Agent (Polling)

```csharp
// Create run
ThreadRun run = await client.Runs.CreateRunAsync(
    thread.Id,
    agent.Id,
    additionalInstructions: "Please address the user as Jane Doe."
);

// Poll for completion
do
{
    await Task.Delay(TimeSpan.FromMilliseconds(500));
    run = await client.Runs.GetRunAsync(thread.Id, run.Id);
}
while (run.Status == RunStatus.Queued || run.Status == RunStatus.InProgress);

// Retrieve messages
await foreach (PersistentThreadMessage message in client.Messages.GetMessagesAsync(
    threadId: thread.Id, 
    order: ListSortOrder.Ascending))
{
    Console.Write($"{message.Role}: ");
    foreach (MessageContent content in message.ContentItems)
    {
        if (content is MessageTextContent textContent)
            Console.WriteLine(textContent.Text);
    }
}
```

### 4. Streaming Response

```csharp
AsyncCollectionResult<StreamingUpdate> stream = client.Runs.CreateRunStreamingAsync(
    thread.Id, 
    agent.Id
);

await foreach (StreamingUpdate update in stream)
{
    if (update.UpdateKind == StreamingUpdateReason.RunCreated)
    {
        Console.WriteLine("--- Run started! ---");
    }
    else if (update is MessageContentUpdate contentUpdate)
    {
        Console.Write(contentUpdate.Text);
    }
    else if (update.UpdateKind == StreamingUpdateReason.RunCompleted)
    {
        Console.WriteLine("\n--- Run completed! ---");
    }
}
```

### 5. Function Calling

```csharp
// Define function tool
FunctionToolDefinition weatherTool = new(
    name: "getCurrentWeather",
    description: "Gets the current weather at a location.",
    parameters: BinaryData.FromObjectAsJson(new
    {
        Type = "object",
        Properties = new
        {
            Location = new { Type = "string", Description = "City and state, e.g. San Francisco, CA" },
            Unit = new { Type = "string", Enum = new[] { "c", "f" } }
        },
        Required = new[] { "location" }
    }, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase })
);

// Create agent with function
PersistentAgent agent = await client.Administration.CreateAgentAsync(
    model: modelDeploymentName,
    name: "Weather Bot",
    instructions: "You are a weather bot.",
    tools: [weatherTool]
);

// Handle function calls during polling
do
{
    await Task.Delay(500);
    run = await client.Runs.GetRunAsync(thread.Id, run.Id);

    if (run.Status == RunStatus.RequiresAction 
        && run.RequiredAction is SubmitToolOutputsAction submitAction)
    {
        List<ToolOutput> outputs = [];
        foreach (RequiredToolCall toolCall in submitAction.ToolCalls)
        {
            if (toolCall is RequiredFunctionToolCall funcCall)
            {
                // Execute function and get result
                string result = ExecuteFunction(funcCall.Name, funcCall.Arguments);
                outputs.Add(new ToolOutput(toolCall, result));
            }
        }
        run = await client.Runs.SubmitToolOutputsToRunAsync(run, outputs, toolApprovals: null);
    }
}
while (run.Status == RunStatus.Queued || run.Status == RunStatus.InP
