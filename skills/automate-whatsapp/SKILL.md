---
name: automate-whatsapp
description: Build WhatsApp automations with Kapso workflows: configure WhatsApp triggers, edit workflow graphs, manage executions, deploy functions, and use databases/integrations for state. Use when automating W
category: AI & Agents
source: antigravity
tags: [node, api, ai, agent, automation, workflow, template]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/automate-whatsapp
---


# Automate WhatsApp

## When to use

Use this skill to build and run WhatsApp automations: workflow CRUD, graph edits, triggers, executions, function management, app integrations, and D1 database operations.

## Setup

Env vars:
- `KAPSO_API_BASE_URL` (host only, no `/platform/v1`)
- `KAPSO_API_KEY`

## How to

### Edit a workflow graph

1. Fetch graph: `node scripts/get-graph.js <workflow_id>` (note the `lock_version`)
2. Edit the JSON (see graph rules below)
3. Validate: `node scripts/validate-graph.js --definition-file <path>`
4. Update: `node scripts/update-graph.js <workflow_id> --expected-lock-version <n> --definition-file <path>`
5. Re-fetch to confirm

For small edits, use `edit-graph.js` with `--old-file` and `--new-file` instead.

If you get a lock_version conflict: re-fetch, re-apply changes, retry with new lock_version.

### Manage triggers

1. List: `node scripts/list-triggers.js <workflow_id>`
2. Create: `node scripts/create-trigger.js <workflow_id> --trigger-type <type> --phone-number-id <id>`
3. Toggle: `node scripts/update-trigger.js --trigger-id <id> --active true|false`
4. Delete: `node scripts/delete-trigger.js --trigger-id <id>`

For inbound_message triggers, first run `node scripts/list-whatsapp-phone-numbers.js` to get `phone_number_id`.

### Debug executions

1. List: `node scripts/list-executions.js <workflow_id>`
2. Inspect: `node scripts/get-execution.js <execution-id>`
3. Get value: `node scripts/get-context-value.js <execution-id> --variable-path vars.foo`
4. Events: `node scripts/list-execution-events.js <execution-id>`

### Create and deploy a function

1. Write code with handler signature (see function rules below)
2. Create: `node scripts/create-function.js --name <name> --code-file <path>`
3. Deploy: `node scripts/deploy-function.js --function-id <id>`
4. Verify: `node scripts/get-function.js --function-id <id>`

### Set up agent node with app integrations

1. Find model: `node scripts/list-provider-models.js`
2. Find account: `node scripts/list-accounts.js --app-slug <slug>` (use `pipedream_account_id`)
3. Find action: `node scripts/search-actions.js --query <word> --app-slug <slug>` (action_id = key)
4. Create integration: `node scripts/create-integration.js --action-id <id> --app-slug <slug> --account-id <id> --configured-props <json>`
5. Add tools to agent node via `flow_agent_app_integration_tools`

### Database CRUD

1. List tables: `node scripts/list-tables.js`
2. Query: `node scripts/query-rows.js --table <name> --filters <json>`
3. Create/update/delete with row scripts

## Graph rules

- Exactly one start node with `id` = `start`
- Never change existing node IDs
- Use `{node_type}_{timestamp_ms}` for new node IDs
- Non-decide nodes have 0 or 1 outgoing `next` edge
- Decide edge labels must match `conditions[].label`
- Edge keys are `source`/`target`/`label` (not `from`/`to`)

For full schema details, see `references/graph-contract.md`.

## Function rules

```js
async function handler(request, env) {
  // Parse input
  const body = await request.json();
  // Use env.KV and env.DB as needed
  return new Response(JSON.stringify({ result: "ok" }));
}
```

- Do NOT use `export`, `export default`, or arrow functions
- Return a `Response` object

## Execution context

Always use this structure:
- `vars` - user-defined variables
- `system` - system variables
- `context` - channel data
- `metadata` - request metadata

## Scripts

### Workflows

| Script | Purpose |
|--------|---------|
| `list-workflows.js` | List workflows (metadata only) |
| `get-workflow.js` | Get workflow metadata |
| `create-workflow.js` | Create a workflow |
| `update-workflow-settings.js` | Update workflow settings |

### Graph

| Script | Purpose |
|--------|---------|
| `get-graph.js` | Get workflow graph + lock_version |
| `edit-graph.js` | Patch graph via string replacement |
| `update-graph.js` | Replace entire graph |
| `validate-graph.js` | Validate graph structure locally |

### Triggers

| Script | Purpose |
|--------|---------|
| `list-triggers.js` | List triggers for a workflow |
| `create-trigger.js` | Create a trigger |
| `update-trigger.js` | Enable/disable a trigger |
| `delete-trigger.js` | Delete a trigger |
| `list-whatsapp-phone-numbers.js` | List phone numbers for trigger setup |

### Executions

| Script | Purpose |
|--------|---------|
| `list-executions.js` | List executions |
| `get-execution.js` | Get execution details |
| `get-context-value.js` | Read value from execution context |
| `update-execution-status.js` | Force execution state |
| `resume-execution.js` | Resume waiting execution |
| `list-execution-events.js` | List execution events |

### Functions

| Script | Purpose |
|--------|---------|
| `list-functions.js` | List project functions |
| `get-function.js` | Get function details + code |
| `create-function.js` | Create a function |
| `update-function.js` | Update function code |
| `deploy-function.js` | Deploy function to runtime |
| `invoke-function.js` | Invok
