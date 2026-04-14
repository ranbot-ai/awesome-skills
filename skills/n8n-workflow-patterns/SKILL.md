---
name: n8n-workflow-patterns
description: Proven architectural patterns for building n8n workflows. 
category: Document Processing
source: antigravity
tags: [python, javascript, node, api, mcp, ai, agent, automation, workflow, template]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/n8n-workflow-patterns
---


# n8n Workflow Patterns

Proven architectural patterns for building n8n workflows.

## When to Use
- You need to choose an architectural pattern for an n8n workflow before building it.
- The task involves webhook processing, API integration, scheduled jobs, database sync, or AI-agent workflow design.
- You want a high-level workflow structure rather than node-by-node troubleshooting.

---

## The 5 Core Patterns

Based on analysis of real workflow usage:

1. **Webhook Processing** (Most Common)
   - Receive HTTP requests → Process → Output
   - Pattern: Webhook → Validate → Transform → Respond/Notify

2. **[HTTP API Integration]**
   - Fetch from REST APIs → Transform → Store/Use
   - Pattern: Trigger → HTTP Request → Transform → Action → Error Handler

3. **Database Operations**
   - Read/Write/Sync database data
   - Pattern: Schedule → Query → Transform → Write → Verify

4. **AI Agent Workflow**
   - AI agents with tools and memory
   - Pattern: Trigger → AI Agent (Model + Tools + Memory) → Output

5. **Scheduled Tasks**
   - Recurring automation workflows
   - Pattern: Schedule → Fetch → Process → Deliver → Log

---

## Pattern Selection Guide

### When to use each pattern:

**Webhook Processing** - Use when:
- Receiving data from external systems
- Building integrations (Slack commands, form submissions, GitHub webhooks)
- Need instant response to events
- Example: "Receive Stripe payment webhook → Update database → Send confirmation"

**HTTP API Integration** - Use when:
- Fetching data from external APIs
- Synchronizing with third-party services
- Building data pipelines
- Example: "Fetch GitHub issues → Transform → Create Jira tickets"

**Database Operations** - Use when:
- Syncing between databases
- Running database queries on schedule
- ETL workflows
- Example: "Read Postgres records → Transform → Write to MySQL"

**AI Agent Workflow** - Use when:
- Building conversational AI
- Need AI with tool access
- Multi-step reasoning tasks
- Example: "Chat with AI that can search docs, query database, send emails"

**Scheduled Tasks** - Use when:
- Recurring reports or summaries
- Periodic data fetching
- Maintenance tasks
- Example: "Daily: Fetch analytics → Generate report → Email team"

---

## Common Workflow Components

All patterns share these building blocks:

### 1. Triggers
- **Webhook** - HTTP endpoint (instant)
- **Schedule** - Cron-based timing (periodic)
- **Manual** - Click to execute (testing)
- **Polling** - Check for changes (intervals)

### 2. Data Sources
- **HTTP Request** - REST APIs
- **Database nodes** - Postgres, MySQL, MongoDB
- **Service nodes** - Slack, Google Sheets, etc.
- **Code** - Custom JavaScript/Python

### 3. Transformation
- **Set** - Map/transform fields
- **Code** - Complex logic
- **IF/Switch** - Conditional routing
- **Merge** - Combine data streams

### 4. Outputs
- **HTTP Request** - Call APIs
- **Database** - Write data
- **Communication** - Email, Slack, Discord
- **Storage** - Files, cloud storage

### 5. Error Handling
- **Error Trigger** - Catch workflow errors
- **IF** - Check for error conditions
- **Stop and Error** - Explicit failure
- **Continue On Fail** - Per-node setting

---

## Workflow Creation Checklist

When building ANY workflow, follow this checklist:

### Planning Phase
- [ ] Identify the pattern (webhook, API, database, AI, scheduled)
- [ ] List required nodes (use search_nodes)
- [ ] Understand data flow (input → transform → output)
- [ ] Plan error handling strategy

### Implementation Phase
- [ ] Create workflow with appropriate trigger
- [ ] Add data source nodes
- [ ] Configure authentication/credentials
- [ ] Add transformation nodes (Set, Code, IF)
- [ ] Add output/action nodes
- [ ] Configure error handling

### Validation Phase
- [ ] Validate each node configuration (validate_node)
- [ ] Validate complete workflow (validate_workflow)
- [ ] Test with sample data
- [ ] Handle edge cases (empty data, errors)

### Deployment Phase
- [ ] Review workflow settings (execution order, timeout, error handling)
- [ ] Activate workflow using `activateWorkflow` operation
- [ ] Monitor first executions
- [ ] Document workflow purpose and data flow

---

## Data Flow Patterns

### Linear Flow
```
Trigger → Transform → Action → End
```
**Use when**: Simple workflows with single path

### Branching Flow
```
Trigger → IF → [True Path]
             └→ [False Path]
```
**Use when**: Different actions based on conditions

### Parallel Processing
```
Trigger → [Branch 1] → Merge
       └→ [Branch 2] ↗
```
**Use when**: Independent operations that can run simultaneously

### Loop Pattern
```
Trigger → Split in Batches → Process → Loop (until done)
```
**Use when**: Processing large datasets in chunks

### Error Handler Pattern
```
Main Flow → [Success Path]
         └→ [Error Trigger → Error Handler]
```
**Use when**: Need separate error handling workflow

---

## Common Gotchas

### 1. Webhook Data Structure
**Problem**: Can't access webhook payload data
