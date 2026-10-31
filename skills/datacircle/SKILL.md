---
name: datacircle
description: Every GTM API plan on datacircle.dev, as one file you download and query. Use it to compare or price a GTM data API. 
category: Business & Marketing
source: antigravity
tags: [python, react, api, mcp, claude, ai, llm, gpt, image, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/datacircle
---


# Datacircle

Datacircle lists all the GTM APIs. This skill gives you every plan on datacircle.dev as one file.

## When to use

Use it to compare or price a GTM data API.

## 1. Download it

```bash
DATA_DIR="$(mktemp -d)" || exit 1
curl --fail --silent --show-error --location --compressed \
  --proto '=https' --proto-redir '=https' --max-time 60 --max-filesize 104857600 \
  --output "$DATA_DIR/datacircle.json" https://datacircle.dev/datacircle.json || exit 1
cd "$DATA_DIR" || exit 1
```

Or the same rows and columns as CSV: `https://datacircle.dev/datacircle.csv`. In the CSV, we write each list or object as JSON.

## 2. The model

One row is one plan of one call. A provider's plan that covers two calls is two rows. Every row has every key below. Prices are in dollars, except `pay`, which is in the plan's `currency`. An item is what a row's API counts, like a profile on LinkedIn profiles or an email on Find email. The table of APIs below gives each API's item.

| Key | Type | Meaning |
|---|---|---|
| `name` | text | The sheet's first column gives each row's name. No two rows on the sheet share a name. The name starts with the provider, then the plan's price. Some names: "API Builderz, $50 monthly", "HarvestAPI, $280 pack", "Crawlbase, pay as you go", "Bright Data, top-up" (a prepaid balance of any amount), "AnyAPI, top-up from $10" (a balance you top up by $10 or more), "free" or "contact us". Two plans with the same price also get the plan's name. We drop any words in the plan's name that the price already gives. If two rows share a name after that, we add the call's method and path to each name. When two names still match, we add the plan's units. When they still match after that, we add the call's name. The sheet's own CSV and JSON files have no name column. datacircle.json and datacircle.csv have a name column with the same names as the sheets. |
| `provider` | text | Who sells the endpoint. On the sheet, the provider's name starts each row's API plan. |
| `api` | text | This column names each row's API. Each API has a sheet in the GTM APIs list. Most sheets share the API's name. For the rest, we give the sheet's name after the API. "Employee profile", on the LinkedIn profiles sheet, returns a person's LinkedIn profile. "Employee email", on the Find email sheet, finds a person's work email. "Email validation", on the Validate email sheet, checks whether an email address takes mail. "Employee phone", on the Find phone sheet, finds a person's phone number. "Company profile", on the LinkedIn company profiles sheet, returns a company's LinkedIn page. "Company headcount" counts a company's staff. "Phone validation", on the Validate phone sheet, checks whether a phone number is valid. "Post comments", on the LinkedIn post comments sheet, returns the comments on a LinkedIn post. "Post reactions", on the LinkedIn post reactions sheet, returns the reactions to a LinkedIn post, each with the person who reacted. "Employee lookalikes", on the Similar people sheet, returns people similar to the person you send. "Company lookalikes", on the Similar companies sheet, returns companies similar to the company you send. "Company technologies" returns the tools a company uses. "Company job count" counts the jobs a company has open on LinkedIn. "Employee posts", on the LinkedIn person posts sheet, returns a person's LinkedIn posts. "Company posts", on the LinkedIn company posts sheet, returns a company's LinkedIn posts. "Company funding" returns a company's funding rounds. "Company jobs", on the Company open jobs sheet, returns the jobs a company has open. "Employee search", on the LinkedIn people search sheet, finds people by job title, company and place. "Company search", on the LinkedIn company search sheet, finds companies by industry, size and place. "Job search", on the LinkedIn job search sheet, finds jobs by title, company and place. "Reverse email lookup" finds the person behind an email address. "Post search", on the LinkedIn post search sheet, finds posts by keyword. "Post details", on the LinkedIn post details sheet, returns a post from the post's URL or ID. "Job details", on the LinkedIn job details sheet, returns a job from the job's URL or ID. "Employee comments", on the LinkedIn person comments sheet, returns the comments a person left on posts. "Employee reactions", on the LinkedIn person reactions sheet, returns the posts a person reacted to. "Post reposts", on the LinkedIn post reposts sheet, returns the people who reposted a LinkedIn post. "Employee recommendations", on the LinkedIn person recommendations sheet, returns the recommendations on a person's LinkedIn profile. "Job lookalikes", on the Similar jobs sheet, returns jobs similar to the job you send. "Employee articles", on the LinkedIn person articles sheet, returns a person's LinkedIn articles. "Company enrichment" returns a company's profile from each seller's own database. "People search" finds people in each seller's own database. "Company 
