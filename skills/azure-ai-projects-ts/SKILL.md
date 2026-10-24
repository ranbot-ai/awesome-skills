---
name: azure-ai-projects-ts
description: High-level SDK for Azure AI Foundry projects with agents, connections, deployments, and evaluations. 
category: Document Processing
source: antigravity
tags: [typescript, api, mcp, ai, agent, gpt, workflow, document, azure, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/azure-ai-projects-ts
---


# Azure AI Projects SDK for TypeScript

High-level SDK for Azure AI Foundry projects with agents, connections, deployments, and evaluations.

## Installation

```bash
npm install @azure/ai-projects @azure/identity
```

For tracing:
```bash
npm install @azure/monitor-opentelemetry @opentelemetry/api
```

## Environment Variables

```bash
AZURE_AI_PROJECT_ENDPOINT=https://<resource>.services.ai.azure.com/api/projects/<project>
MODEL_DEPLOYMENT_NAME=gpt-4o
```

## Authentication

```typescript
import { AIProjectClient } from "@azure/ai-projects";
import { DefaultAzureCredential } from "@azure/identity";

const client = new AIProjectClient(
  process.env.AZURE_AI_PROJECT_ENDPOINT!,
  new DefaultAzureCredential()
);
```

## SDK generation and effects

These independent fragments span version-sensitive project/agent APIs. Pin the actual package/API generation and verify available operation groups before use. Confirm tenant/project and budget before agent runs, dataset uploads or tools; code interpreter/MCP can execute code or disclose private data. `getWithCredentials` returns secrets and is not a default discovery operation. Cleanup must target only resources created and owned by this task.

## Operation Groups

| Group | Purpose |
|-------|---------|
| `client.agents` | Create and manage AI agents |
| `client.connections` | List connected Azure resources |
| `client.deployments` | List model deployments |
| `client.datasets` | Upload and manage datasets |
| `client.indexes` | Create and manage search indexes |
| `client.evaluators` | Manage evaluation metrics |
| `client.memoryStores` | Manage agent memory |

## Getting OpenAI Client

```typescript
const openAIClient = await client.getOpenAIClient();

// Use for responses
const response = await openAIClient.responses.create({
  model: "gpt-4o",
  input: "What is the capital of France?"
});

// Use for conversations
const conversation = await openAIClient.conversations.create({
  items: [{ type: "message", role: "user", content: "Hello!" }]
});
```

## Agents

### Create Agent

```typescript
const agent = await client.agents.createVersion("my-agent", {
  kind: "prompt",
  model: "gpt-4o",
  instructions: "You are a helpful assistant."
});
```

### Agent with Tools

```typescript
// Code Interpreter
const agent = await client.agents.createVersion("code-agent", {
  kind: "prompt",
  model: "gpt-4o",
  instructions: "You can execute code.",
  tools: [{ type: "code_interpreter", container: { type: "auto" } }]
});

// File Search
const agent = await client.agents.createVersion("search-agent", {
  kind: "prompt",
  model: "gpt-4o",
  tools: [{ type: "file_search", vector_store_ids: [vectorStoreId] }]
});

// Web Search
const agent = await client.agents.createVersion("web-agent", {
  kind: "prompt",
  model: "gpt-4o",
  tools: [{
    type: "web_search_preview",
    user_location: { type: "approximate", country: "US", city: "Seattle" }
  }]
});

// Azure AI Search
const agent = await client.agents.createVersion("aisearch-agent", {
  kind: "prompt",
  model: "gpt-4o",
  tools: [{
    type: "azure_ai_search",
    azure_ai_search: {
      indexes: [{
        project_connection_id: connectionId,
        index_name: "my-index",
        query_type: "simple"
      }]
    }
  }]
});

// Function Tool
const agent = await client.agents.createVersion("func-agent", {
  kind: "prompt",
  model: "gpt-4o",
  tools: [{
    type: "function",
    function: {
      name: "get_weather",
      description: "Get weather for a location",
      strict: true,
      parameters: {
        type: "object",
        properties: { location: { type: "string" } },
        required: ["location"]
      }
    }
  }]
});

// MCP Tool
const agent = await client.agents.createVersion("mcp-agent", {
  kind: "prompt",
  model: "gpt-4o",
  tools: [{
    type: "mcp",
    server_label: "my-mcp",
    server_url: "https://mcp-server.example.com",
    require_approval: "always"
  }]
});
```

### Run Agent

```typescript
const openAIClient = await client.getOpenAIClient();

// Create conversation
const conversation = await openAIClient.conversations.create({
  items: [{ type: "message", role: "user", content: "Hello!" }]
});

// Generate response using agent
const response = await openAIClient.responses.create(
  { conversation: conversation.id },
  { body: { agent: { name: agent.name, type: "agent_reference" } } }
);

// Cleanup
await openAIClient.conversations.delete(conversation.id);
await client.agents.deleteVersion(agent.name, agent.version);
```

## Connections

```typescript
// List all connections
for await (const conn of client.connections.list()) {
  console.log(conn.name, conn.type);
}

// Get connection by name
const conn = await client.connections.get("my-connection");

// Get connection with credentials
const connWithCreds = await client.connections.getWithCredentials("my-connection");

// Get default connection by type
const defaultAzureOpenAI = await client.connections.getDefault("AzureOpenAI", true);
