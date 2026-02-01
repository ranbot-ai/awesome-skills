---
name: azure-functions
description: Expert patterns for Azure Functions development including isolated worker model, Durable Functions orchestration, cold start optimization, and production patterns. Covers .NET, Python, and Node.js pro
category: Development & Code Tools
source: antigravity
tags: [python, javascript, typescript, node, ai, azure]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/azure-functions
---


# Azure Functions

## Patterns

### Isolated Worker Model (.NET)

Modern .NET execution model with process isolation

### Node.js v4 Programming Model

Modern code-centric approach for TypeScript/JavaScript

### Python v2 Programming Model

Decorator-based approach for Python functions

## Anti-Patterns

### ❌ Blocking Async Calls

### ❌ New HttpClient Per Request

### ❌ In-Process Model for New Projects

## ⚠️ Sharp Edges

| Issue | Severity | Solution |
|-------|----------|----------|
| Issue | high | ## Use async pattern with Durable Functions |
| Issue | high | ## Use IHttpClientFactory (Recommended) |
| Issue | high | ## Always use async/await |
| Issue | medium | ## Configure maximum timeout (Consumption) |
| Issue | high | ## Use isolated worker for new projects |
| Issue | medium | ## Configure Application Insights properly |
| Issue | medium | ## Check extension bundle (most common) |
| Issue | medium | ## Add warmup trigger to initialize your code |
