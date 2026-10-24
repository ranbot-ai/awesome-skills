---
name: datacircle
description: Every GTM API plan on datacircle.dev, as one file you download and query. Use it to compare or price a GTM data API. 
category: Business & Marketing
source: antigravity
tags: [python, react, api, mcp, claude, ai, llm, rag]
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

One row is one plan of one call. A provider's plan that covers two calls is two rows. Every row has every key below. Prices are in dollars, except `pay`, which is in the plan's `currency`.

| Key | Type | Meaning |
|---|---|---|
| `name` | text | The row's name, unique on the sheet: the provider, then the plan's price, like "API Builderz, $50 monthly", "HarvestAPI, $280 pack", "Crawlbase, pay as you go", "Bright Data, top-up" (a prepaid balance of any amount), "AnyAPI, top-up from $10" (a balance you top up by $10 or more), "free" or "contact us". If two plans share a price, we add the plan's name, then the call's method and path, its units and the call's name, until no two rows share a name. We build the name for the sheet and leave it out of the sheet's CSV and JSON. datacircle.json and datacircle.csv have the name from its API's sheet. |
| `provider` | text | Who sells the endpoint. On the sheet, it starts each row's API plan. |
| `api` | text | This column names each row's API. "Employee profile" returns a person's LinkedIn profile, on LinkedIn profiles. "Cached employee profile" returns it from the provider's copy of LinkedIn, on Cached LinkedIn profiles, which lists the LinkedIn profile plans whose Freshness says a copy. "Employee email" finds a person's work email, on Find email. "Cached employee email", on the Find cached email sheet, finds a person's work email in the provider's stored data. "Email validation" checks whether an address takes mail, on Validate email. On the Cached email validation sheet, "Cached email validation" may answer from data the provider keeps, without asking the mail server. "Employee phone" finds a person's phone number, on Find phone. "Cached employee phone", on the Find cached phone sheet, finds a person's phone number in the provider's stored data. "Company profile" returns a company's LinkedIn page, on LinkedIn company profiles. "Cached company profile", on the Cached LinkedIn company profiles sheet, returns a company's LinkedIn page from the provider's copy of LinkedIn. "Company headcount" counts a company's staff, on its own sheet. "Cached company headcount", on the Cached company headcount sheet, counts a company's staff from the provider's stored data. "Phone validation" checks whether a phone number is valid, on Validate phone. "Cached phone validation", on the Cached phone validation sheet, checks a phone number against data the provider has stored. "Post comments" returns the comments on a LinkedIn post, on LinkedIn post comments. "Post reactions" returns who reacted to a LinkedIn post and how, on LinkedIn post reactions. "Employee lookalikes" returns people similar to the one you send, on Similar people. "Company lookalikes" returns companies similar to the one you send, on Similar companies. "Company technologies" returns the tools a company uses, on its own sheet. "Cached company technologies" returns the tools a company uses, from a copy the provider saved earlier. "Company job count" counts the jobs a company has open on LinkedIn, on its own sheet. "Employee posts" returns a person's LinkedIn posts, on LinkedIn person posts. "Company posts" returns a company's LinkedIn posts, on LinkedIn company posts. "Cached employee posts" and "Cached company posts", on Cached LinkedIn person posts and Cached LinkedIn company posts, return them from the provider's copy of LinkedIn. "Company funding" returns a company's funding rounds, on its own sheet. "Cached company funding", on the Cached company funding sheet, returns them from the provider's stored data. "Company jobs" returns the jobs a company has open, on Company open jobs. "Employee search" finds people by job title, company and place, on LinkedIn people search. "Cached employee search", on the Cached LinkedIn people search sheet, finds people in the provider's copy of LinkedIn. "Company search" finds companies by industry, size and place, on LinkedIn company search. "Cached company search" finds companies by industry, size and place in the provider's copy of LinkedIn. It is on the Cached LinkedIn company search sheet. "Job search" finds jobs by title, company and place, on LinkedIn job search. "Cached job search" finds jobs by title, company and place in a copy of LinkedIn's jobs. It is on the Cached LinkedIn job search sheet. "Reverse email lookup" finds the person behind an emai
