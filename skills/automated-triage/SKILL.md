---
name: automated-triage
description: Triage Monte Carlo alerts interactively or build an automated workflow. Fetch, score, and troubleshoot alerts using MCP tools now, or design a reusable workflow that runs on a schedule. 
category: Document Processing
source: antigravity
tags: [mcp, ai, agent, automation, workflow, design, document, security]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/automated-triage
---


# Monte Carlo Automated Triage

This skill helps you design, test, and deploy an automated triage agent for Monte Carlo alerts. Rather than a fixed workflow, it gives you the building blocks — a set of MCP tools, a description of each triage stage, and a working example — so you can build a process that matches how your team actually responds to alerts.

> **Monte Carlo tool routing (required):** Always call Monte Carlo MCP tools through this plugin's
> bundled server, whose fully-qualified tool names are
> `mcp__plugin_mc-agent-toolkit_monte-carlo-mcp__<tool>` (e.g.
> `mcp__plugin_mc-agent-toolkit_monte-carlo-mcp__get_alerts`). Bare tool names used in this skill
> (`get_alerts`, `search`, `get_table`, …) refer to that bundled server. If the session also has a
> separately-configured `monte-carlo-mcp` server, do **not** route to it — it may point at a
> different endpoint or credentials.

Read the reference files before proceeding:

- Triage stages and customisation: `references/triage-stages.md` (relative to this file)
- Working example workflow: `references/triage-example.md` (relative to this file)

---

## When to activate this skill

Activate when the user:

- Wants to triage or investigate recent Monte Carlo alerts (interactively or automated)
- Wants to set up automated triage for Monte Carlo alerts
- Asks to run agentic triage or investigate recent alert activity
- Wants to understand what triage tools are available and how to use them
- Is building or refining a triage prompt for their environment
- Wants to move from manual alert review to automated or semi-automated triage

## When NOT to activate this skill

Do not activate when the user is:

- Investigating a specific known incident (help them directly)
- Creating or configuring monitors (use the monitoring-advisor skill)
- Running impact analysis before a code change (use the prevent skill)

---

## Available MCP tools

All tools are available via the `monte-carlo-mcp` MCP server.

| Tool                             | Toolset  | Purpose                                                         |
| -------------------------------- | -------- | --------------------------------------------------------------- |
| `get_alerts`                          | default  | Fetch recent alerts for a time window                                                                             |
| `alert_assessment`                    | default  | Score an alert by incident likelihood and potential impact (HIGH/MEDIUM/LOW each)                                 |
| `run_troubleshooting_agent`           | default  | Run the Monte Carlo Troubleshooting Agent on a single alert; async by default — returns immediately, reuses existing results when available |
| `get_troubleshooting_agent_results`   | default  | Poll an async troubleshooting run by `incident_id`; returns status (`not_found`/`running`/`success`/`failed`) and results when complete |
| `update_alert`                        | default  | Update an alert's status and/or declare an incident by setting severity                                           |
| `set_alert_owner`                     | default  | Assign an owner to an alert by email                                                                              |
| `create_or_update_alert_comment`      | default  | Post or update a triage comment on an alert                                                                       |
| `mark_event_as_normal`                | default  | Mark all anomaly events in an alert as normal, triggering ML threshold recalibration to prevent re-alerting on the same pattern |

---

## How to approach automated triage

Read `references/triage-stages.md` for a full description of each stage and how to customise it. The high-level flow is:

1. **Fetch alerts** — decide which alerts to triage and over what time window
2. **Initial investigation** — score every alert by incident likelihood and potential impact using `alert_assessment`
3. **Deep troubleshooting** — run `run_troubleshooting_agent` on high-signal alerts to get root cause analysis
4. **Classify** — use the troubleshooting output to classify each alert
5. **Take actions** — post comments, update statuses, message Slack, create tickets

The triage process is not fixed. Read the stages reference to understand the options and tradeoffs at each step, then design a workflow that fits your team's needs.

## The longer-term direction

Most teams move through roughly the same arc, though the pace and path vary:

- **Start with recommendations.** Run manually and have the agent post comments describing what it found and what it would do — no actual status changes or external actions. Use this to tune the workflow until the output matches how your team would respond manually.
- **Automate, still in recommendation mode.** Once the output looks right, put it on a schedule. Keep it in recommendation mode while you validate it's behaving well on real traffic.
- **Replace recommendati
