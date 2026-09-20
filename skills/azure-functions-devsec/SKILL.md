---
name: azure-functions-devsec
description: Build serverless applications on Azure Functions. Configure triggers, bindings, and deployment. Use when implementing serverless workloads on Azure. 
category: Document Processing
source: antigravity
tags: [python, javascript, node, api, ai, agent, template, document, security, azure]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/azure-functions-devsec
---


# Azure Functions

Build and deploy serverless applications with Azure Functions. Covers function app creation, trigger and binding configuration, deployment strategies, real code examples in Python and Node.js, and production best practices.

## When to Use

- You need event-driven compute that scales automatically to zero.
- You are building APIs, webhooks, or background processing pipelines.
- You want per-execution billing without managing servers.
- You need to respond to Azure service events (Blob Storage, Service Bus, Cosmos DB changes).
- You are implementing lightweight microservices or scheduled tasks.

## Prerequisites

```bash
# Install Azure CLI
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

# Install Azure Functions Core Tools v4
npm install -g azure-functions-core-tools@4

# Verify installation
func --version

# Login
az login
az account set --subscription "my-subscription-id"

# Create supporting resources
az group create --name functions-rg --location eastus

az storage account create \
  --name myfuncstorageacct \
  --resource-group functions-rg \
  --location eastus \
  --sku Standard_LRS
```

## Function App Creation

### Consumption Plan (Pay-per-execution)

```bash
# Python function app on Consumption plan
az functionapp create \
  --resource-group functions-rg \
  --consumption-plan-location eastus \
  --runtime python \
  --runtime-version 3.11 \
  --functions-version 4 \
  --name myapp-func \
  --storage-account myfuncstorageacct \
  --os-type Linux

# Node.js function app
az functionapp create \
  --resource-group functions-rg \
  --consumption-plan-location eastus \
  --runtime node \
  --runtime-version 20 \
  --functions-version 4 \
  --name myapp-node-func \
  --storage-account myfuncstorageacct \
  --os-type Linux
```

### Premium Plan (VNet integration, no cold start)

```bash
# Create Premium plan
az functionapp plan create \
  --resource-group functions-rg \
  --name myapp-premium-plan \
  --location eastus \
  --sku EP1 \
  --is-linux true

# Create function app on Premium plan
az functionapp create \
  --resource-group functions-rg \
  --plan myapp-premium-plan \
  --runtime python \
  --runtime-version 3.11 \
  --functions-version 4 \
  --name myapp-premium-func \
  --storage-account myfuncstorageacct
```

## Trigger and Binding Examples

### HTTP Trigger -- Python

```python
# function_app.py (v2 programming model)
import azure.functions as func
import json
import logging

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

@app.route(route="users/{userId}", methods=["GET"])
def get_user(req: func.HttpRequest) -> func.HttpResponse:
    user_id = req.route_params.get("userId")
    logging.info(f"Fetching user: {user_id}")

    if not user_id:
        return func.HttpResponse(
            json.dumps({"error": "userId is required"}),
            status_code=400,
            mimetype="application/json"
        )

    user = {"id": user_id, "name": "Jane Doe", "email": "jane@example.com"}
    return func.HttpResponse(
        json.dumps(user),
        status_code=200,
        mimetype="application/json"
    )

@app.route(route="users", methods=["POST"])
def create_user(req: func.HttpRequest) -> func.HttpResponse:
    try:
        body = req.get_json()
    except ValueError:
        return func.HttpResponse(
            json.dumps({"error": "Invalid JSON"}),
            status_code=400,
            mimetype="application/json"
        )

    logging.info(f"Creating user: {body.get('name')}")
    return func.HttpResponse(
        json.dumps({"id": "new-id", **body}),
        status_code=201,
        mimetype="application/json"
    )
```

### HTTP Trigger -- Node.js

```javascript
// src/functions/httpTrigger.js (v4 programming model)
const { app } = require("@azure/functions");

app.http("getUser", {
  methods: ["GET"],
  authLevel: "function",
  route: "users/{userId}",
  handler: async (request, context) => {
    const userId = request.params.userId;
    context.log(`Fetching user: ${userId}`);

    if (!userId) {
      return { status: 400, jsonBody: { error: "userId is required" } };
    }

    const user = { id: userId, name: "Jane Doe", email: "jane@example.com" };
    return { status: 200, jsonBody: user };
  },
});

app.http("createUser", {
  methods: ["POST"],
  authLevel: "function",
  route: "users",
  handler: async (request, context) => {
    const body = await request.json();
    context.log(`Creating user: ${body.name}`);

    return { status: 201, jsonBody: { id: "new-id", ...body } };
  },
});
```

### Blob Trigger -- Python

```python
@app.blob_trigger(arg_name="blob", path="uploads/{name}",
                   connection="AzureWebJobsStorage")
def process_upload(blob: func.InputStream):
    logging.info(f"Processing blob: {blob.name}, Size: {blob.length} bytes")
    content = blob.read()
    # Process file content here
```

### Timer Trigger -- Python

```python
@app.timer_trigger(schedule="0 */5 * * * *", arg_name="timer",
             
