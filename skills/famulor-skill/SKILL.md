---
name: famulor-skill
description: Operate Famulor assistants, communication history, campaigns, knowledge, automations, telephony, and workspace administration through its hosted MCP server. 
category: Document Processing
source: antigravity
tags: [api, mcp, claude, ai, agent, automation, workflow, template, design, document]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/famulor-skill
---


# Famulor

Use Famulor through the hosted Streamable HTTP MCP server:

```text
https://app.famulor.io/mcp
```

This skills-only package does not install or configure the MCP connection. Add the endpoint as a remote Streamable HTTP server in the user's MCP client, then let that client run its OAuth flow. A workspace API key can also authenticate trusted server-to-server clients, but never ask a user to paste a key into chat or place one in files, commands, logs, or source control.

If the Famulor MCP server is unavailable in the current client, help the user connect it and stop before claiming to have read or changed their account. Do not substitute an undocumented REST endpoint.

## When to Use

- Use when a request needs real Famulor workspace data or an authenticated Famulor action.
- Use when configuring or operating assistants, communication history, campaigns, knowledge, automations, telephony, billing, or workspace settings.
- Do not use for generic voice-agent advice that does not require Famulor.

## Limitations

- Static tool tables are a dated routing snapshot; the authenticated server's live `tools/list` schema is authoritative.
- Available tools, fields, scopes, plan features, prices, limits, and provider behavior can differ by workspace and change over time.
- This skill cannot grant missing consent, roles, scopes, plan entitlements, provider approvals, or regulatory authorization.
- External calls, messages, purchases, migrations, and integrations may have costs or effects outside Famulor; verify their returned status instead of assuming completion or rollback.

## Route to the smallest toolset

Use only the group or groups needed for the request. A narrower URL keeps discovery and model context manageable:

```text
https://app.famulor.io/mcp?toolsets=assistants,calls
```

Read the linked reference only for the relevant group. Each reference contains every tool currently assigned to that group; the live `tools/list` schema remains authoritative.

| Toolset | Use for | Current tools | Reference |
| --- | --- | ---: | --- |
| `assistants` | Assistants, versions, models, voices, reusable tools, bookings, tests, and integrations | 56 | [assistants](references/toolsets/assistants.md) |
| `calls` | Calls, unified history, transcripts, QA, callbacks, and live control | 15 | [calls](references/toolsets/calls.md) |
| `campaigns` | Campaigns, Audience contacts, leads, segments, consent, suppression, and outbound limits | 34 | [campaigns](references/toolsets/campaigns.md) |
| `messaging` | WhatsApp, Messenger, email, Slack, connectors, templates, and sender profiles | 44 | [messaging](references/toolsets/messaging.md) |
| `telephony` | Phone numbers, SIP trunks, caller IDs, carriers, and number verification | 27 | [telephony](references/toolsets/telephony.md) |
| `knowledge` | Knowledge bases, documents, FAQs, websites, and connected drives | 20 | [knowledge](references/toolsets/knowledge.md) |
| `dashboards` | Dashboards, analytics, widgets, and layout | 19 | [dashboards](references/toolsets/dashboards.md) |
| `automations` | Automations, connections, CRM sync, routines, and runs | 28 | [automations](references/toolsets/automations.md) |
| `billing` | Balance, usage, transactions, invoices, billing recovery, and referrals | 7 | [billing](references/toolsets/billing.md) |
| `settings` | Account, workspaces, API keys, retention, memory, domains, and sessions | 20 | [settings](references/toolsets/settings.md) |
| `platform` | Authorized white-label reseller customer administration | 6 | [platform](references/toolsets/platform.md) |
| `migration` | Previewing and importing supported Famulor 1.0 resources | 2 | [migration](references/toolsets/migration.md) |
| `tasks` | Durable exports, simulations, crawls, and campaign preparation | 4 | [tasks](references/toolsets/tasks.md) |

The full snapshot contains 282 tools. `list_mcp_toolsets` can report the groups visible to the current credential. The public `assistant-history` directory profile is intentionally limited to 11 read-only tools; use it only when the user specifically wants that restricted connection.

## Operating workflow

1. Resolve the requested outcome, current workspace, and permitted scope. Ask only for missing choices that materially affect the result.
2. Discover the live tool schema. Never infer arguments from a similar REST endpoint, an old example, or a static ID.
3. Read current state before changing it. Resolve resource IDs with list/get tools and preserve fields the user did not ask to change.
4. Choose the smallest tool call that achieves the request. Use a preview, test, or simulation when the domain offers one and it is useful.
5. Before an external or difficult-to-reverse effect, ensure the user has explicitly authorized the exact target and action. If the current request already supplies that authorization, do not ask again.
6. Verify the result with the corresponding read tool or returned status. For asynchronous work, follow the 
