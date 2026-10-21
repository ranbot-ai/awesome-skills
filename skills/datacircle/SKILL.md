---
name: datacircle
description: Every GTM API plan on datacircle.dev, as one file you download and query. Use it to compare or price a GTM data API. 
category: AI & Agents
source: antigravity
tags: [python, react, api, mcp, claude, ai, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/datacircle
---


# Datacircle

Datacircle lists all the GTM APIs. This skill gives you every plan on datacircle.dev as one file.

## When to use

Use it to compare or price a GTM data API.

## 1. Download it

```bash
curl -sL --compressed -o datacircle.json https://datacircle.dev/datacircle.json
```

Or the same rows and columns as CSV: `https://datacircle.dev/datacircle.csv`. In the CSV, we write each list or object as JSON.

## 2. The model

One row is one plan of one call. A provider's plan that covers two calls is two rows. Every row has every key below. Prices are in dollars, except `pay`, which is in the plan's `currency`.

| Key | Type | Meaning |
|---|---|---|
| `name` | text | The row's name, unique on the sheet: the provider, then the plan's price, like "API Builderz, $50 monthly", "HarvestAPI, $280 pack", "Crawlbase, pay as you go", "Bright Data, top-up" (a prepaid balance of any amount), "free" or "contact us". If two plans share a price, we add the plan's name, then the call's method and path, its units and the call's name, until no two rows share a name. We build the name for the sheet and leave it out of the sheet's CSV and JSON. datacircle.json and datacircle.csv have the name from its API's sheet. |
| `provider` | text | Who sells the endpoint. On the sheet, it starts each row's API plan. |
| `api` | text | This column names each row's API. "Employee profile" returns a person's LinkedIn profile, on LinkedIn profiles. "Cached employee profile" returns it from the provider's copy of LinkedIn, on Cached LinkedIn profiles, which lists the LinkedIn profile plans whose Freshness says a copy. "Employee email" finds a person's work email, on Find email. "Cached employee email", on the Find cached email sheet, finds a person's work email in the provider's stored data. "Email validation" checks whether an address takes mail, on Validate email. "Employee phone" finds a person's phone number, on Find phone. "Company profile" returns a company's LinkedIn page, on LinkedIn company profiles. "Cached company profile", on the Cached LinkedIn company profiles sheet, returns a company's LinkedIn page from the provider's copy of LinkedIn. "Company headcount" counts a company's staff, on its own sheet. "Cached company headcount", on the Cached company headcount sheet, counts a company's staff from the provider's stored data. "Phone validation" checks whether a phone number is valid, on Validate phone. "Post comments" returns the comments on a LinkedIn post, on LinkedIn post comments. "Post reactions" returns who reacted to a LinkedIn post and how, on LinkedIn post reactions. "Employee lookalikes" returns people similar to the one you send, on Similar people. "Company lookalikes" returns companies similar to the one you send, on Similar companies. "Company technologies" returns the tools a company uses, on its own sheet. "Company job count" counts the jobs a company has open on LinkedIn, on its own sheet. "Employee posts" returns a person's LinkedIn posts, on LinkedIn person posts. "Company posts" returns a company's LinkedIn posts, on LinkedIn company posts. "Company funding" returns a company's funding rounds, on its own sheet. "Company jobs" returns the jobs a company has open, on Company open jobs. "Employee search" finds people by job title, company and place, on LinkedIn people search. "Company search" finds companies by industry, size and place, on LinkedIn company search. "Job search" finds jobs by title, company and place, on LinkedIn job search. "Reverse email lookup" finds the person behind an email, on its own sheet. "Post search" finds posts by keyword, on LinkedIn post search. "Post details" returns a post from its URL or ID, on LinkedIn post details. "Job details" returns a job from its URL or ID, on LinkedIn job details. "Employee comments" returns the comments a person left on posts, on LinkedIn person comments. "Employee reactions" returns the posts a person reacted to, on LinkedIn person reactions. "Post reposts" returns the people who reposted a LinkedIn post, on LinkedIn post reposts. "Employee recommendations" returns the recommendations on a person's LinkedIn profile, on LinkedIn person recommendations. "Job lookalikes" returns jobs similar to the one you send, on Similar jobs. "Employee articles" returns a person's LinkedIn articles, on LinkedIn person articles. "Company enrichment" returns a company's profile from the provider's own database, on Company enrichment. "Cached company enrichment", on the Cached company enrichment sheet, returns a company's profile from the provider's stored data. "People search" finds people in the provider's own database. "Cached people search", on the Cached people search sheet, finds people in the provider's stored data. "Company discovery" finds companies in the provider's own database. "Cached company discovery", on the Cached company discovery sheet, finds companies in the provider's stored data. "Job postings" finds job postings in the provider's own database. "Job p
