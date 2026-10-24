---
name: aws-agentic-ai
description: AWS Bedrock AgentCore comprehensive expert for deploying and managing AI agents at scale. Use when working with any AgentCore service including Gateway, Runtime, Memory, Identity, Code Interpreter, Br
category: AI & Agents
source: antigravity
tags: [api, mcp, claude, ai, agent, llm, automation, workflow, template, document]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/aws-agentic-ai
---


# AWS Bedrock AgentCore
## When to Use

Use this skill when you need aWS Bedrock AgentCore comprehensive expert for deploying and managing AI agents at scale. Use when working with any AgentCore service including Gateway, Runtime, Memory, Identity, Code Interpreter, Browser, Observability, Agent Registry, or Evaluations. Covers agent deployment, MCP...


AWS Bedrock AgentCore provides a complete platform for deploying and scaling AI agents with nine core services. This skill covers service selection, deployment patterns, and integration workflows using AWS CLI.

**How to use this skill**: Identify the service(s) the user needs from the table below, then read the corresponding service README before responding. For cross-service patterns (credentials, security, registry integration), check the Cross-Service Resources section. Verify AWS-specific details using the MCP documentation tools.

## AWS Documentation Requirement

Verify current AWS facts through available primary documentation tools or official AWS documentation. The following are optional upstream integrations, not tools bundled by this single-file catalog skill:
- **AgentCore-specific docs** (`mcp__acdocs__*`) — upstream integration that may provide `search_agentcore_docs` and `fetch_agentcore_doc` for AgentCore documentation
- **General AWS docs** (`mcp__aws-mcp__*` or `mcp__*awsdocs*__*`) — may be configured separately for broader AWS documentation

Prefer the AgentCore docs MCP for AgentCore-specific questions. If these tools are unavailable, use official documentation; do not install a new server unless requested.

## Available Services

| Service | Use For | Documentation |
|---------|---------|---------------|
| **Gateway** | Converting REST APIs to MCP tools | [`services/gateway/README.md`](https://github.com/zxkane/aws-skills/tree/main/plugins/aws-agentic-ai/skills/aws-agentic-ai/services/gateway/README.md) |
| **Runtime** | Deploying and scaling agents | [`services/runtime/README.md`](https://github.com/zxkane/aws-skills/tree/main/plugins/aws-agentic-ai/skills/aws-agentic-ai/services/runtime/README.md) |
| **Memory** | Managing conversation state | [`services/memory/README.md`](https://github.com/zxkane/aws-skills/tree/main/plugins/aws-agentic-ai/skills/aws-agentic-ai/services/memory/README.md) |
| **Identity** | Credential and access management | [`services/identity/README.md`](https://github.com/zxkane/aws-skills/tree/main/plugins/aws-agentic-ai/skills/aws-agentic-ai/services/identity/README.md) |
| **Code Interpreter** | Secure code execution in sandboxes | [`services/code-interpreter/README.md`](https://github.com/zxkane/aws-skills/tree/main/plugins/aws-agentic-ai/skills/aws-agentic-ai/services/code-interpreter/README.md) |
| **Browser** | Web automation and scraping | [`services/browser/README.md`](https://github.com/zxkane/aws-skills/tree/main/plugins/aws-agentic-ai/skills/aws-agentic-ai/services/browser/README.md) |
| **Observability** | Tracing and monitoring | [`services/observability/README.md`](https://github.com/zxkane/aws-skills/tree/main/plugins/aws-agentic-ai/skills/aws-agentic-ai/services/observability/README.md) |
| **Agent Registry** | Catalog, discover, and govern agents/tools (Preview) | [`services/registry/README.md`](https://github.com/zxkane/aws-skills/tree/main/plugins/aws-agentic-ai/skills/aws-agentic-ai/services/registry/README.md) |
| **Evaluations** | Automated agent quality assessment (LLM-as-a-Judge) | [`services/evaluations/README.md`](https://github.com/zxkane/aws-skills/tree/main/plugins/aws-agentic-ai/skills/aws-agentic-ai/services/evaluations/README.md) |

This catalog contains no service README or executable templates locally. Read the selected upstream revision and inspect every dependency before implementation; do not claim those references were reviewed from their titles. Verify account/region/IAM, costs, data retention and publication scope before provisioning or sending conversation/trace data to cloud services.

## Common Workflows

### Deploying a Gateway Target

Read [`services/gateway/README.md`](https://github.com/zxkane/aws-skills/tree/main/plugins/aws-agentic-ai/skills/aws-agentic-ai/services/gateway/README.md) before implementing — Gateway setup involves deployment strategies, IAM, and auth choices that vary significantly by use case.

1. Upload OpenAPI schema to S3
2. *(API Key auth only)* Create credential provider and store API key
3. Create gateway target linking schema (and credentials if using API key)
4. Verify target status and test connectivity

> Credential provider is only needed for API key authentication. Lambda targets use IAM roles, and MCP servers use OAuth.

### Managing Credentials

Read [`cross-service/credential-management.md`](https://github.com/zxkane/aws-skills/tree/main/plugins/aws-agentic-ai/skills/aws-agentic-ai/cross-service/credential-management.md) first — credential patterns differ across services and getting them wrong causes hard-to-debug auth failures.

1. U
