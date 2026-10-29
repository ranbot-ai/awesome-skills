---
name: mcp-builder
description: Guide for creating high-quality MCP (Model Context Protocol) servers that enable LLMs to interact with external services through well-designed tools. Use when building MCP servers to integrate externa
category: Development & Code Tools
source: anthropic
tags: [python, typescript, node, markdown, api, mcp, ai, agent, workflow, design]
url: https://github.com/anthropics/skills/tree/main/skills/mcp-builder
---


# MCP Server Development Guide

## Overview

Create MCP (Model Context Protocol) servers that enable LLMs to interact with external services through well-designed tools. The quality of an MCP server is measured by how well it enables LLMs to accomplish real-world tasks.

---

# Process

## 🚀 High-Level Workflow

Creating a high-quality MCP server involves four main phases:

### Phase 1: Deep Research and Planning

#### 1.1 Understand Modern MCP Design

**API Coverage vs. Workflow Tools:**
Balance comprehensive API endpoint coverage with specialized workflow tools. Workflow tools can be more convenient for specific tasks, while comprehensive coverage gives agents flexibility to compose operations. Performance varies by client—some clients benefit from code execution that combines basic tools, while others work better with higher-level workflows. When uncertain, prioritize comprehensive API coverage.

**Tool Naming and Discoverability:**
Clear, descriptive tool names help agents find the right tools quickly. Use consistent prefixes (e.g., `github_create_issue`, `github_list_repos`) and action-oriented naming.

**Context Management:**
Agents benefit from concise tool descriptions and the ability to filter/paginate results. Design tools that return focused, relevant data. Some clients support code execution which can help agents filter and process data efficiently.

**Actionable Error Messages:**
Error messages should guide agents toward solutions with specific suggestions and next steps.

#### 1.2 Study MCP Protocol Documentation

**Navigate the MCP specification:**

Start with the sitemap to find relevant pages: `https://modelcontextprotocol.io/sitemap.xml`

Then fetch specific pages with `.md` suffix for markdown format (e.g., `https://modelcontextprotocol.io/specification/draft.md`).

Key pages to review:
- Specification overview and architecture
- Transport mechanisms (streamable HTTP, stdio)
- Tool, resource, and prompt definitions

#### 1.3 Study Framework Documentation

**Recommended stack:**
- **Language**: TypeScript (high-quality SDK support and good compatibility in many execution environments e.g. MCPB. Plus AI models are good at generating TypeScript code, benefiting from its broad usage, static typing and good linting tools)
- **Transport**: Streamable HTTP for remote servers, using stateless JSON (simpler to scale and maintain, as opposed to stateful sessions and streaming responses). stdio for local servers.

**Load framework documentation:**

- **MCP Best Practices**: [📋 View Best Practices](./reference/mcp_best_practices.md) - Core guidelines

**For TypeScript (recommended):**

The TypeScript SDK has two major versions. Pick one before writing code:
- **v2** (`@modelcontextprotocol/server`): the current stable release. Use it for new servers.
- **v1** (`@modelcontextprotocol/sdk`): receives bug and security fixes only. Use it only when the project's `package.json` already depends on `@modelcontextprotocol/sdk`, or migrate that project with `npx @modelcontextprotocol/codemod@latest v1-to-v2 .`

If the project already uses v1, tell the user once, in a sentence or two, that v2 (`@modelcontextprotocol/server`) is the current stable release, that v1 receives only bug and security fixes, and that `npx @modelcontextprotocol/codemod@latest v1-to-v2 .` migrates the project. Then continue with v1 unless the user asks to migrate.

Don't mix the two in one project: v1 code samples (imports from `@modelcontextprotocol/sdk/...`) don't apply to v2.

- **TypeScript SDK (v2)**: Use WebFetch to load `https://raw.githubusercontent.com/modelcontextprotocol/typescript-sdk/main/README.md`; the full docs index is `https://ts.sdk.modelcontextprotocol.io/v2/llms.txt`
- [⚡ TypeScript Guide (v2)](./reference/node_mcp_server_v2.md) - TypeScript patterns and examples
- For v1 projects only: `https://raw.githubusercontent.com/modelcontextprotocol/typescript-sdk/v1.x/README.md` and the [TypeScript Guide (v1)](./reference/node_mcp_server.md)

**For Python:**
- **Python SDK**: Use WebFetch to load `https://raw.githubusercontent.com/modelcontextprotocol/python-sdk/main/README.md`
- [🐍 Python Guide](./reference/python_mcp_server.md) - Python patterns and examples

#### 1.4 Plan Your Implementation

**Understand the API:**
Review the service's API documentation to identify key endpoints, authentication requirements, and data models. Use web search and WebFetch as needed.

**Tool Selection:**
Prioritize comprehensive API coverage. List endpoints to implement, starting with the most common operations.

---

### Phase 2: Implementation

#### 2.1 Set Up Project Structure

See language-specific guides for project setup:
- [⚡ TypeScript Guide (v2)](./reference/node_mcp_server_v2.md) - Project structure, package.json, tsconfig.json ([v1](./reference/node_mcp_server.md) for existing v1 projects)
- [🐍 Python Guide](./reference/python_mcp_server.md) - Module organization, dependencies

#### 2.2 Implement Core Infrastructure

Create 
