---
name: azure-ai-projects-dotnet
description: Azure AI Projects SDK for .NET. High-level client for Azure AI Foundry projects including agents, connections, datasets, deployments, evaluations, and indexes. Use for AI Foundry project management, v
category: AI & Agents
source: antigravity
tags: [python, api, mcp, ai, agent, gpt, workflow, azure, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/azure-ai-projects-dotnet
---


# Azure.AI.Projects (.NET)

High-level SDK for Azure AI Foundry project operations including agents, connections, datasets, deployments, evaluations, and indexes.

## Installation

```bash
dotnet add package Azure.AI.Projects
dotnet add package Azure.Identity

# Optional: For versioned agents with OpenAI extensions
dotnet add package Azure.AI.Projects.OpenAI --prerelease

# Optional: For low-level agent operations
dotnet add package Azure.AI.Agents.Persistent --prerelease
```

**Current Versions**: GA v1.1.0, Preview v1.2.0-beta.5

## Environment Variables

```bash
PROJECT_ENDPOINT=https://<resource>.services.ai.azure.com/api/projects/<project>
MODEL_DEPLOYMENT_NAME=gpt-4o-mini
CONNECTION_NAME=<your-connection-name>
AI_SEARCH_CONNECTION_NAME=<ai-search-connection>
```

## Authentication

```csharp
using Azure.Identity;
using Azure.AI.Projects;

var endpoint = Environment.GetEnvironmentVariable("PROJECT_ENDPOINT");
AIProjectClient projectClient = new AIProjectClient(
    new Uri(endpoint), 
    new DefaultAzureCredential());
```

## Client Hierarchy

```
AIProjectClient
├── Agents          → AIProjectAgentsOperations (versioned agents)
├── Connections     → ConnectionsClient
├── Datasets        → DatasetsClient
├── Deployments     → DeploymentsClient
├── Evaluations     → EvaluationsClient
├── Evaluators      → EvaluatorsClient
├── Indexes         → IndexesClient
├── Telemetry       → AIProjectTelemetry
├── OpenAI          → ProjectOpenAIClient (preview)
└── GetPersistentAgentsClient() → PersistentAgentsClient
```

## Core Workflows

### 1. Get Persistent Agents Client

```csharp
// Get low-level agents client from project client
PersistentAgentsClient agentsClient = projectClient.GetPersistentAgentsClient();

// Create agent
PersistentAgent agent = await agentsClient.Administration.CreateAgentAsync(
    model: "gpt-4o-mini",
    name: "Math Tutor",
    instructions: "You are a personal math tutor.");

// Create thread and run
PersistentAgentThread thread = await agentsClient.Threads.CreateThreadAsync();
await agentsClient.Messages.CreateMessageAsync(thread.Id, MessageRole.User, "Solve 3x + 11 = 14");
ThreadRun run = await agentsClient.Runs.CreateRunAsync(thread.Id, agent.Id);

// Poll for completion
do
{
    await Task.Delay(500);
    run = await agentsClient.Runs.GetRunAsync(thread.Id, run.Id);
}
while (run.Status == RunStatus.Queued || run.Status == RunStatus.InProgress);

// Get messages
await foreach (var msg in agentsClient.Messages.GetMessagesAsync(thread.Id))
{
    foreach (var content in msg.ContentItems)
    {
        if (content is MessageTextContent textContent)
            Console.WriteLine(textContent.Text);
    }
}

// Cleanup
await agentsClient.Threads.DeleteThreadAsync(thread.Id);
await agentsClient.Administration.DeleteAgentAsync(agent.Id);
```

### 2. Versioned Agents with Tools (Preview)

```csharp
using Azure.AI.Projects.OpenAI;

// Create agent with web search tool
PromptAgentDefinition agentDefinition = new(model: "gpt-4o-mini")
{
    Instructions = "You are a helpful assistant that can search the web",
    Tools = {
        ResponseTool.CreateWebSearchTool(
            userLocation: WebSearchToolLocation.CreateApproximateLocation(
                country: "US",
                city: "Seattle",
                region: "Washington"
            )
        ),
    }
};

AgentVersion agentVersion = await projectClient.Agents.CreateAgentVersionAsync(
    agentName: "myAgent",
    options: new(agentDefinition));

// Get response client
ProjectResponsesClient responseClient = projectClient.OpenAI.GetProjectResponsesClientForAgent(agentVersion.Name);

// Create response
ResponseResult response = responseClient.CreateResponse("What's the weather in Seattle?");
Console.WriteLine(response.GetOutputText());

// Cleanup
projectClient.Agents.DeleteAgentVersion(agentName: agentVersion.Name, agentVersion: agentVersion.Version);
```

### 3. Connections

```csharp
// List all connections
foreach (AIProjectConnection connection in projectClient.Connections.GetConnections())
{
    Console.WriteLine($"{connection.Name}: {connection.ConnectionType}");
}

// Get specific connection
AIProjectConnection conn = projectClient.Connections.GetConnection(
    connectionName, 
    includeCredentials: true);

// Get default connection
AIProjectConnection defaultConn = projectClient.Connections.GetDefaultConnection(
    includeCredentials: false);
```

### 4. Deployments

```csharp
// List all deployments
foreach (AIProjectDeployment deployment in projectClient.Deployments.GetDeployments())
{
    Console.WriteLine($"{deployment.Name}: {deployment.ModelName}");
}

// Filter by publisher
foreach (var deployment in projectClient.Deployments.GetDeployments(modelPublisher: "Microsoft"))
{
    Console.WriteLine(deployment.Name);
}

// Get specific deployment
ModelDeployment details = (ModelDeployment)projectClient.Deployments.GetDeployment("gpt-4o-mini");
```

### 5. Datasets

```csharp
// Upload single file
FileDataset file
