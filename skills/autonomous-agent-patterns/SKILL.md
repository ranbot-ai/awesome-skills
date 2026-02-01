---
name: autonomous-agent-patterns
description: Design patterns for building autonomous coding agents. Covers tool integration, permission systems, browser automation, and human-in-the-loop workflows. Use when building AI agents, designing tool API
category: AI & Agents
source: antigravity
tags: [python, node, markdown, api, mcp, claude, ai, agent, llm, gpt]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/autonomous-agent-patterns
---


# 🕹️ Autonomous Agent Patterns

> Design patterns for building autonomous coding agents, inspired by [Cline](https://github.com/cline/cline) and [OpenAI Codex](https://github.com/openai/codex).

## When to Use This Skill

Use this skill when:

- Building autonomous AI agents
- Designing tool/function calling APIs
- Implementing permission and approval systems
- Creating browser automation for agents
- Designing human-in-the-loop workflows

---

## 1. Core Agent Architecture

### 1.1 Agent Loop

```
┌─────────────────────────────────────────────────────────────┐
│                     AGENT LOOP                               │
│                                                              │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐              │
│  │  Think   │───▶│  Decide  │───▶│   Act    │              │
│  │ (Reason) │    │ (Plan)   │    │ (Execute)│              │
│  └──────────┘    └──────────┘    └──────────┘              │
│       ▲                               │                     │
│       │         ┌──────────┐          │                     │
│       └─────────│ Observe  │◀─────────┘                     │
│                 │ (Result) │                                │
│                 └──────────┘                                │
└─────────────────────────────────────────────────────────────┘
```

```python
class AgentLoop:
    def __init__(self, llm, tools, max_iterations=50):
        self.llm = llm
        self.tools = {t.name: t for t in tools}
        self.max_iterations = max_iterations
        self.history = []

    def run(self, task: str) -> str:
        self.history.append({"role": "user", "content": task})

        for i in range(self.max_iterations):
            # Think: Get LLM response with tool options
            response = self.llm.chat(
                messages=self.history,
                tools=self._format_tools(),
                tool_choice="auto"
            )

            # Decide: Check if agent wants to use a tool
            if response.tool_calls:
                for tool_call in response.tool_calls:
                    # Act: Execute the tool
                    result = self._execute_tool(tool_call)

                    # Observe: Add result to history
                    self.history.append({
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "content": str(result)
                    })
            else:
                # No more tool calls = task complete
                return response.content

        return "Max iterations reached"

    def _execute_tool(self, tool_call) -> Any:
        tool = self.tools[tool_call.name]
        args = json.loads(tool_call.arguments)
        return tool.execute(**args)
```

### 1.2 Multi-Model Architecture

```python
class MultiModelAgent:
    """
    Use different models for different purposes:
    - Fast model for planning
    - Powerful model for complex reasoning
    - Specialized model for code generation
    """

    def __init__(self):
        self.models = {
            "fast": "gpt-3.5-turbo",      # Quick decisions
            "smart": "gpt-4-turbo",        # Complex reasoning
            "code": "claude-3-sonnet",     # Code generation
        }

    def select_model(self, task_type: str) -> str:
        if task_type == "planning":
            return self.models["fast"]
        elif task_type == "analysis":
            return self.models["smart"]
        elif task_type == "code":
            return self.models["code"]
        return self.models["smart"]
```

---

## 2. Tool Design Patterns

### 2.1 Tool Schema

```python
class Tool:
    """Base class for agent tools"""

    @property
    def schema(self) -> dict:
        """JSON Schema for the tool"""
        return {
            "name": self.name,
            "description": self.description,
            "parameters": {
                "type": "object",
                "properties": self._get_parameters(),
                "required": self._get_required()
            }
        }

    def execute(self, **kwargs) -> ToolResult:
        """Execute the tool and return result"""
        raise NotImplementedError

class ReadFileTool(Tool):
    name = "read_file"
    description = "Read the contents of a file from the filesystem"

    def _get_parameters(self):
        return {
            "path": {
                "type": "string",
                "description": "Absolute path to the file"
            },
            "start_line": {
                "type": "integer",
                "description": "Line to start reading from (1-indexed)"
            },
            "end_line": {
                "type": "integer",
                "description": "Line to stop reading at (inclusive)"
            }
        }

    def _get_required(self):
        return ["path"]

    def execute(self, path: str, start_line: int = None, end_line: int = None) -> ToolResult:
        try:
            with open(path, 'r') as f
