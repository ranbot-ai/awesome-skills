---
name: ai-dev-jobs-mcp
description: Search indexed AI and ML jobs, inspect listings and employers, match roles, and view salary and market stats via AI Dev Jobs MCP 
category: Document Processing
source: antigravity
tags: [python, api, mcp, claude, ai, agent, llm, workflow, template, design]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/ai-dev-jobs-mcp
---


# AI Dev Jobs MCP

## Overview

AI Dev Jobs is a remote MCP server that gives AI agents access to a live index of AI and ML job listings. Coverage and market statistics change; retrieve current results with timestamps and do not treat a contributed historical snapshot as current market evidence. Agents can search jobs by role, location, or company, retrieve full job details, list hiring companies, match roles to a profile, and get salary or aggregate market statistics. It is designed for AI agents that assist with job searching, recruiting, or labor market analysis.

## When to Use This Skill

- Use when helping a user search for AI or ML engineering jobs
- Use when an agent needs to look up which companies are hiring for specific AI roles
- Use when building recruiting or talent-matching workflows
- Use when analyzing the AI job market (open positions, top companies, role distribution)

## MCP Configuration

Add the AI Dev Jobs MCP server to your client configuration. The endpoint uses streamable HTTP and has historically been documented as unauthenticated; verify current access requirements.

### Claude Desktop / Cursor / Windsurf

```json
{
  "mcpServers": {
    "ai-dev-jobs": {
      "url": "https://aidevboard.com/mcp"
    }
  }
}
```

Verify actual available tool schemas and access. A host configuration template does not prove the endpoint is available or that a connection succeeded.

## Privacy and source verification

Search with the minimum necessary skills/preferences; transmitting a private CV or identifying candidate details requires explicit consent. Do not submit applications, contact recruiters or configure monitoring without the corresponding user request. Verify listing dates, location/remote eligibility, salary currency/period and application URL against the employer's original page; exclude stale or suspicious listings. Market medians require a disclosed sample and missing-salary policy.

## Available Tools

### `search_jobs`

Search the job index by keyword, location, company, or work arrangement. Returns matching listings with title, company, location, and salary information.

```
search_jobs({ query: "machine learning engineer", location: "remote" })
```

### `get_job`

Retrieve full details for a specific job listing by ID, including description, requirements, salary range, and application link.

```
get_job({ id: "abc123" })
```

### `list_companies`

List all companies in the index with their open position counts. Useful for discovering which companies are actively hiring.

```
list_companies({})
```

### `get_company`

Retrieve details for a specific company, including available AI roles when exposed by the endpoint.

```
get_company({ id: "openai" })
```

### `get_stats`

Get aggregate statistics about the job market: total listings, top companies by open roles, role distribution, and location breakdown.

```
get_stats({})
```

### `match_jobs`

Match jobs against a candidate profile, skills list, or preferences.

```
match_jobs({ skills: ["python", "llm", "pytorch"], workplace: "remote" })
```

### `get_salary_data`

Retrieve salary statistics for roles, tags, levels, or locations when available.

```
get_salary_data({ tag: "llm", level: "senior" })
```

### `list_tags`

List indexed tags that can be used to filter searches or salary analysis.

```
list_tags({})
```

## Examples

### Example 1: Find Remote ML Jobs

```text
Use @ai-dev-jobs-mcp to find remote machine learning engineer positions.
```

The agent will call `search_jobs({ query: "machine learning engineer", location: "remote" })` and return matching listings.

### Example 2: Check Which Companies Are Hiring

```text
Use @ai-dev-jobs-mcp to list all companies currently hiring for AI roles.
```

The agent will call `list_companies({})` and return companies sorted by number of open positions.

### Example 3: Get Job Market Overview

```text
Use @ai-dev-jobs-mcp to show current AI job market statistics.
```

The agent will call `get_stats({})` and return aggregate data on listings, top employers, and role distribution.

### Example 4: Get Full Job Details

```text
Use @ai-dev-jobs-mcp to get the full details for job ID abc123.
```

The agent will call `get_job({ id: "abc123" })` and return the complete listing with requirements and application link.

### Example 5: Match Jobs to a Candidate Profile

```text
Use @ai-dev-jobs-mcp to match remote LLM roles to a senior Python and PyTorch profile.
```

The agent will call `match_jobs({ skills: ["python", "llm", "pytorch"], workplace: "remote" })` and return suitable listings.

### Example 6: Compare Salary Data

```text
Use @ai-dev-jobs-mcp to compare senior LLM salary data.
```

The agent will call `get_salary_data({ tag: "llm", level: "senior" })` and summarize available compensation ranges.

## Best Practices

- Use `search_jobs` with specific keywords for targeted results rather than broad queries
- Use `list_companies` to discover companies, then `search_jobs` filtered by
