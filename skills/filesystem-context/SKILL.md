---
name: filesystem-context
description: Use for file-based context management, dynamic context discovery, and reducing context window bloat. Offload context to files for just-in-time loading. 
category: AI & Agents
source: antigravity
tags: [python, api, ai, agent, design, langchain, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/filesystem-context
---


# Filesystem-Based Context Engineering

The filesystem provides a single interface through which agents can flexibly store, retrieve, and update an effectively unlimited amount of context. This pattern addresses the fundamental constraint that context windows are limited while tasks often require more information than fits in a single window.

The core insight is that files enable dynamic context discovery: agents pull relevant context on demand rather than carrying everything in the context window. This contrasts with static context, which is always included regardless of relevance.

## When to Use
Activate this skill when:
- Tool outputs are bloating the context window
- Agents need to persist state across long trajectories
- Sub-agents must share information without direct message passing
- Tasks require more context than fits in the window
- Building agents that learn and update their own instructions
- Implementing scratch pads for intermediate results
- Terminal outputs or logs need to be accessible to agents

## Core Concepts

Context engineering can fail in four predictable ways. First, when the context an agent needs is not in the total available context. Second, when retrieved context fails to encapsulate needed context. Third, when retrieved context far exceeds needed context, wasting tokens and degrading performance. Fourth, when agents cannot discover niche information buried in many files.

The filesystem addresses these failures by providing a persistent layer where agents write once and read selectively, offloading bulk content while preserving the ability to retrieve specific information through search tools.

## Detailed Topics

### The Static vs Dynamic Context Trade-off

**Static Context**
Static context is always included in the prompt: system instructions, tool definitions, and critical rules. Static context consumes tokens regardless of task relevance. As agents accumulate more capabilities (tools, skills, instructions), static context grows and crowds out space for dynamic information.

**Dynamic Context Discovery**
Dynamic context is loaded on-demand when relevant to the current task. The agent receives minimal static pointers (names, descriptions, file paths) and uses search tools to load full content when needed.

Dynamic discovery is more token-efficient because only necessary data enters the context window. It can also improve response quality by reducing potentially confusing or contradictory information.

The trade-off: dynamic discovery requires the model to correctly identify when to load additional context. This works well with current frontier models but may fail with less capable models that do not recognize when they need more information.

### Pattern 1: Filesystem as Scratch Pad

**The Problem**
Tool calls can return massive outputs. A web search may return 10k tokens of raw content. A database query may return hundreds of rows. If this content enters the message history, it remains for the entire conversation, inflating token costs and potentially degrading attention to more relevant information.

**The Solution**
Write large tool outputs to files instead of returning them directly to the context. The agent then uses targeted retrieval (grep, line-specific reads) to extract only the relevant portions.

**Implementation**
```python
def handle_tool_output(output: str, threshold: int = 2000) -> str:
    if len(output) < threshold:
        return output
    
    # Write to scratch pad
    file_path = f"scratch/{tool_name}_{timestamp}.txt"
    write_file(file_path, output)
    
    # Return reference instead of content
    key_summary = extract_summary(output, max_tokens=200)
    return f"[Output written to {file_path}. Summary: {key_summary}]"
```

The agent can then use `grep` to search for specific patterns or `read_file` with line ranges to retrieve targeted sections.

**Benefits**
- Reduces token accumulation over long conversations
- Preserves full output for later reference
- Enables targeted retrieval instead of carrying everything

### Pattern 2: Plan Persistence

**The Problem**
Long-horizon tasks require agents to make plans and follow them. But as conversations extend, plans can fall out of attention or be lost to summarization. The agent loses track of what it was supposed to do.

**The Solution**
Write plans to the filesystem. The agent can re-read its plan at any point, reminding itself of the current objective and progress. This is sometimes called "manipulating attention through recitation."

**Implementation**
Store plans in structured format:
```yaml
# scratch/current_plan.yaml
objective: "Refactor authentication module"
status: in_progress
steps:
  - id: 1
    description: "Audit current auth endpoints"
    status: completed
  - id: 2
    description: "Design new token validation flow"
    status: in_progress
  - id: 3
    description: "Implement and test changes"
    status: pending
```

The agent reads this file at the start of each turn or when it n
