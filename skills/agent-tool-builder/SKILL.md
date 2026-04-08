---
name: agent-tool-builder
description: Tools are how AI agents interact with the world. A well-designed tool is the difference between an agent that works and one that hallucinates, fails silently, or costs 10x more tokens than necessary. 
category: AI & Agents
source: antigravity
tags: [python, typescript, api, mcp, claude, ai, agent, llm, automation, design]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/agent-tool-builder
---


# Agent Tool Builder

Tools are how AI agents interact with the world. A well-designed tool is the
difference between an agent that works and one that hallucinates, fails
silently, or costs 10x more tokens than necessary.

This skill covers tool design from schema to error handling. JSON Schema
best practices, description writing that actually helps the LLM, validation,
and the emerging MCP standard that's becoming the lingua franca for AI tools.

Key insight: Tool descriptions are more important than tool implementations.
The LLM never sees your code - it only sees the schema and description.

## Principles

- Description quality > implementation quality for LLM accuracy
- Aim for fewer than 20 tools - more causes confusion
- Every tool needs explicit error handling - silent failures poison agents
- Return strings, not objects - LLMs process text
- Validation gates before execution - reject, fix, or escalate, never silent fail
- Test tools with the LLM, not just unit tests

## Capabilities

- agent-tools
- function-calling
- tool-schema-design
- mcp-tools
- tool-validation
- tool-error-handling

## Scope

- multi-agent-coordination → multi-agent-orchestration
- agent-memory → agent-memory-systems
- api-design → api-designer
- llm-prompting → prompt-engineering

## Tooling

### Standards

- JSON Schema - When: All tool definitions Note: The universal format for tool schemas
- MCP (Model Context Protocol) - When: Building reusable, cross-platform tools Note: Anthropic's open standard, widely adopted

### Frameworks

- Anthropic SDK - When: Claude-based agents Note: Beta tool runner handles most complexity
- OpenAI Functions - When: OpenAI-based agents Note: Use strict mode for guaranteed schema compliance
- Vercel AI SDK - When: Multi-provider tool handling Note: Abstracts differences between providers
- LangChain Tools - When: LangChain-based agents Note: Converts MCP tools to LangChain format

## Patterns

### Tool Schema Design

Creating clear, unambiguous JSON Schema for tools

**When to use**: Defining any new tool for an agent

# TOOL SCHEMA BEST PRACTICES:

## 1. Detailed Descriptions (Most Important)
"""
BAD - Too vague:
{
  "name": "get_stock_price",
  "description": "Gets stock price",
  "input_schema": {
    "type": "object",
    "properties": {
      "ticker": {"type": "string"}
    }
  }
}

GOOD - Comprehensive:
{
  "name": "get_stock_price",
  "description": "Retrieves the current stock price for a given ticker
    symbol. The ticker symbol must be a valid symbol for a publicly
    traded company on a major US stock exchange like NYSE or NASDAQ.
    Returns the latest trade price in USD. Use when the user asks
    about current or recent stock prices. Does NOT provide historical
    data, company info, or predictions.",
  "input_schema": {
    "type": "object",
    "properties": {
      "ticker": {
        "type": "string",
        "description": "The stock ticker symbol, e.g. AAPL for Apple Inc."
      }
    },
    "required": ["ticker"]
  }
}
"""

## 2. Parameter Descriptions
"""
Every parameter needs:
- What it is
- Format expected
- Example value
- Edge cases/limitations

{
  "location": {
    "type": "string",
    "description": "City and state/country. Format: 'City, State' for US
      (e.g., 'San Francisco, CA') or 'City, Country' for international
      (e.g., 'Tokyo, Japan'). Do not use ZIP codes or coordinates."
  },
  "unit": {
    "type": "string",
    "enum": ["celsius", "fahrenheit"],
    "description": "Temperature unit. Defaults to user's locale if not
      specified. Use 'fahrenheit' for US users, 'celsius' for others."
  }
}
"""

## 3. Use Enums When Possible
"""
Enums constrain the LLM to valid values:

"priority": {
  "type": "string",
  "enum": ["low", "medium", "high", "critical"],
  "description": "Task priority level"
}

"action": {
  "type": "string",
  "enum": ["create", "read", "update", "delete"],
  "description": "The CRUD operation to perform"
}
"""

## 4. Required vs Optional
"""
Be explicit about what's required:

{
  "type": "object",
  "properties": {
    "query": {...},      // Required
    "limit": {...},      // Optional with default
    "offset": {...}      // Optional
  },
  "required": ["query"],
  "additionalProperties": false  // Strict mode
}
"""

### Tool with Input Examples

Using examples to guide LLM tool usage

**When to use**: Complex tools with nested objects or format-sensitive inputs

# TOOL USE EXAMPLES (Anthropic Beta Feature):

"""
Examples show Claude concrete patterns that schemas can't express.
Improves accuracy from 72% to 90% on complex operations.
"""

{
  "name": "create_calendar_event",
  "description": "Creates a calendar event with optional attendees and reminders",
  "input_schema": {
    "type": "object",
    "properties": {
      "title": {"type": "string", "description": "Event title"},
      "start_time": {
        "type": "string",
        "description": "ISO 8601 datetime, e.g. 2024-03-15T14:00:00Z"
      },
      "durat
