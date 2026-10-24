---
name: apify-linkedin-jobs-scraper
description: Search and export LinkedIn job postings with salary, seniority, recruiter and company fields using the harshmaur/linkedin-jobs-scraper Apify Actor. No LinkedIn login. 
category: Development & Code Tools
source: antigravity
tags: [react, markdown, api, mcp, claude, ai, agent, llm, workflow, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/apify-linkedin-jobs-scraper
---


# LinkedIn Jobs Scraper

Turn a job-market question into one run of `harshmaur/linkedin-jobs-scraper` and return one row per job. The author describes an Actor that covers keyword search, pasted search URLs, company enrichment and searches past LinkedIn's limit of about 1,000 results. The work is to pick the right input fields and to keep the job count in budget.

Disclosure: the Actor is paid per result and is built by the skill author. Links carry no affiliate parameters.

## When to Use

Use for LinkedIn job searches, salary comparisons, hiring research and job-board exports.

## Example prompts

Prompts this skill handles:

- "Find product manager jobs in London from the last 24 hours."
- "Export 500 remote React developer jobs in the US with salary and company size."
- "Which companies in Germany posted data engineer jobs this week? Give me the recruiter when there is one."
- "Scrape this LinkedIn search: https://www.linkedin.com/jobs/search/?keywords=devops&location=Canada&f_TPR=r604800"

Out of scope (the boundary):

- "Apply to these jobs for me" or "message the recruiter" — the Actor only reads public job pages.
- "Scrape these LinkedIn profiles" or "find people who work at X" — this Actor returns jobs, not people. Use a profile Actor from the Apify Store.

## Prerequisites

- Apify account ([sign up](https://apify.com)). Check current credits, Actor prices and platform charges before choosing a budget.
- Authentication via one of:
  - `apify login` (OAuth, if you use the Apify CLI)
  - `APIFY_TOKEN` environment variable
  - Token from [Apify Console → Settings → Integrations](https://console.apify.com/settings/integrations)
- Apify CLI (`npm install -g apify-cli`), or the Apify MCP server (see "Calling the Actor").

## Workflow

### Step 1 — Map the request to input fields

| The user gives you | Field | Notes |
|---|---|---|
| A job title, skill or role | `keywords` | Short words work best: `"data engineer"`, not a sentence. |
| A city, country or "remote" | `location` | Free text as LinkedIn takes it: `"Berlin"`, `"United States"`, `"Remote"`. |
| "today", "this week", "this month" | `datePosted` | `"1"` (24 h), `"7"`, `"30"`. Provider-described filter; verify returned timestamps for freshness. |
| remote, hybrid, on-site | `workplaceType` | `remote`, `hybrid`, `on-site`. Not exact (see Gotchas). |
| full-time, contract, internship | `jobType` | `full-time`, `part-time`, `contract`, `temporary`, `internship`. Not exact. |
| junior, senior, director | `experienceLevel` | `internship`, `entry`, `associate`, `mid-senior`, `director`, `executive`. Not exact. |
| A LinkedIn job search URL | `startUrls` | `[{"url": "..."}]`. Search URLs only (`/jobs/search/?...`). The URL keeps its own filters, including company (`f_C`), Easy Apply (`f_AL`) and under 10 applicants (`f_EA`). The form filters above do not apply to it. |
| "how many" | `maxItems` | One total for the whole run, shared by every search. Default 50. `0` means no limit: never send `0` without a cost check. |
| company size, website, headquarters | `scrapeCompany: true` | No extra charge. |
| only the list, fast | `scrapeDetails: false` | Search-card fields only: title, company, location, date, logo, URL. No description, salary or recruiter. |
| more than about 1,000 jobs for one search | `splitByLocation: true` + `splitCountry` | Runs the search in each large city of the country and removes duplicates. Countries: `us`, `uk`, `ca`, `au`, `in`, `de`, `fr`, `nl`, `es`, `ie`, `ae`, `sg`, `br`. It replaces `location`. |
| "send each job to Slack, Notion or Sheets" | `mcpConnector` + `mcpTarget` (+ `mcpMessage`) | Needs an MCP connector that the user authorized in Apify Console. See `references/gotchas.md`. |

You must give at least one of `keywords`, `location` or `startUrls`. Without them the run fails at once with a "Provide a Job title" message, and nothing is charged.

### Step 2 — Build the input

Start small and change only what the request needs:

```json
{
  "keywords": "data engineer",
  "location": "Berlin",
  "datePosted": "7",
  "maxItems": 50,
  "scrapeDetails": true,
  "scrapeCompany": false
}
```

Do not pass `proxy`. Fetch the live schema when a field is in doubt:

```bash
apify actors info "harshmaur/linkedin-jobs-scraper" --input --json \
  --user-agent apify-awesome-skills/apify-linkedin-jobs-scraper
```

### Step 3 — Estimate the cost, then run

The price is per job in the dataset. There is no start fee, and details, recruiter and company data cost nothing extra:

| Apify plan | Per 1,000 jobs |
|---|---|
| Free | $1.00 |
| Starter | $0.47 |
| Scale | $0.43 |
| Business and higher | $0.40 |

`cost ≈ maxItems × price per job`. Use the Free price when you do not know the plan. These are historical illustrative prices, not a spending ceiling. Verify the live Actor pricing and account plan, include platform charges, and stay within the user-authorized budget; when no budget is authorized, obtain one before a paid run. Never use un
