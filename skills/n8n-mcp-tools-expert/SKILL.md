---
name: n8n-mcp-tools-expert
description: Expert guide for using n8n-mcp MCP tools effectively. Use when searching for nodes, validating configurations, accessing templates, managing workflows, or using any n8n-mcp tool. Provides tool selecti
category: Document Processing
source: antigravity
tags: [python, javascript, node, markdown, api, mcp, ai, agent, workflow, template]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/n8n-mcp-tools-expert
---


# n8n MCP Tools Expert

Master guide for using n8n-mcp MCP server tools to build workflows.

## When to Use This Skill

Use this skill when:
- Searching for n8n nodes
- Validating n8n configurations
- Accessing n8n templates
- Managing n8n workflows
- Using any n8n-mcp tool
- Need guidance on tool selection or parameter formats

---

## Tool Categories

n8n-mcp provides tools organized into categories:

1. **Node Discovery** → [SEARCH_GUIDE.md](SEARCH_GUIDE.md)
2. **Configuration Validation** → [VALIDATION_GUIDE.md](VALIDATION_GUIDE.md)
3. **Workflow Management** → [WORKFLOW_GUIDE.md](WORKFLOW_GUIDE.md)
4. **Template Library** - Search and deploy 2,700+ real workflows
5. **Documentation & Guides** - Tool docs, AI agent guide, Code node guides

---

## Quick Reference

### Most Used Tools (by success rate)

| Tool | Use When | Speed |
|------|----------|-------|
| `search_nodes` | Finding nodes by keyword | <20ms |
| `get_node` | Understanding node operations (detail="standard") | <10ms |
| `validate_node` | Checking configurations (mode="full") | <100ms |
| `n8n_create_workflow` | Creating workflows | 100-500ms |
| `n8n_update_partial_workflow` | Editing workflows (MOST USED!) | 50-200ms |
| `validate_workflow` | Checking complete workflow | 100-500ms |
| `n8n_deploy_template` | Deploy template to n8n instance | 200-500ms |

---

## Tool Selection Guide

### Finding the Right Node

**Workflow**:
```
1. search_nodes({query: "keyword"})
2. get_node({nodeType: "nodes-base.name"})
3. [Optional] get_node({nodeType: "nodes-base.name", mode: "docs"})
```

**Example**:
```javascript
// Step 1: Search
search_nodes({query: "slack"})
// Returns: nodes-base.slack

// Step 2: Get details
get_node({nodeType: "nodes-base.slack"})
// Returns: operations, properties, examples (standard detail)

// Step 3: Get readable documentation
get_node({nodeType: "nodes-base.slack", mode: "docs"})
// Returns: markdown documentation
```

**Common pattern**: search → get_node (18s average)

### Validating Configuration

**Workflow**:
```
1. validate_node({nodeType, config: {}, mode: "minimal"}) - Check required fields
2. validate_node({nodeType, config, profile: "runtime"}) - Full validation
3. [Repeat] Fix errors, validate again
```

**Common pattern**: validate → fix → validate (23s thinking, 58s fixing per cycle)

### Managing Workflows

**Workflow**:
```
1. n8n_create_workflow({name, nodes, connections})
2. n8n_validate_workflow({id})
3. n8n_update_partial_workflow({id, operations: [...]})
4. n8n_validate_workflow({id}) again
5. n8n_update_partial_workflow({id, operations: [{type: "activateWorkflow"}]})
```

**Common pattern**: iterative updates (56s average between edits)

---

## Critical: nodeType Formats

**Two different formats** for different tools!

### Format 1: Search/Validate Tools
```javascript
// Use SHORT prefix
"nodes-base.slack"
"nodes-base.httpRequest"
"nodes-base.webhook"
"nodes-langchain.agent"
```

**Tools that use this**:
- search_nodes (returns this format)
- get_node
- validate_node
- validate_workflow

### Format 2: Workflow Tools
```javascript
// Use FULL prefix
"n8n-nodes-base.slack"
"n8n-nodes-base.httpRequest"
"n8n-nodes-base.webhook"
"@n8n/n8n-nodes-langchain.agent"
```

**Tools that use this**:
- n8n_create_workflow
- n8n_update_partial_workflow

### Conversion

```javascript
// search_nodes returns BOTH formats
{
  "nodeType": "nodes-base.slack",          // For search/validate tools
  "workflowNodeType": "n8n-nodes-base.slack"  // For workflow tools
}
```

---

## Common Mistakes

### Mistake 1: Wrong nodeType Format

**Problem**: "Node not found" error

```javascript
// WRONG
get_node({nodeType: "slack"})  // Missing prefix
get_node({nodeType: "n8n-nodes-base.slack"})  // Wrong prefix

// CORRECT
get_node({nodeType: "nodes-base.slack"})
```

### Mistake 2: Using detail="full" by Default

**Problem**: Huge payload, slower response, token waste

```javascript
// WRONG - Returns 3-8K tokens, use sparingly
get_node({nodeType: "nodes-base.slack", detail: "full"})

// CORRECT - Returns 1-2K tokens, covers 95% of use cases
get_node({nodeType: "nodes-base.slack"})  // detail="standard" is default
get_node({nodeType: "nodes-base.slack", detail: "standard"})
```

**When to use detail="full"**:
- Debugging complex configuration issues
- Need complete property schema with all nested options
- Exploring advanced features

**Better alternatives**:
1. `get_node({detail: "standard"})` - for operations list (default)
2. `get_node({mode: "docs"})` - for readable documentation
3. `get_node({mode: "search_properties", propertyQuery: "auth"})` - for specific property

### Mistake 3: Not Using Validation Profiles

**Problem**: Too many false positives OR missing real errors

**Profiles**:
- `minimal` - Only required fields (fast, permissive)
- `runtime` - Values + types (recommended for pre-deployment)
- `ai-friendly` - Reduce false positives (for AI configuration)
- `strict` - Maximum validation (for production)

```javas
