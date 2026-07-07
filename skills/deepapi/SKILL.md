---
name: deepapi
description: Use DeepAPI for supported scraping, research, and email workflows with explicit credentials and approval. 
category: Development & Code Tools
source: antigravity
tags: [node, markdown, api, claude, ai, agent, automation, workflow, image, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/deepapi
---


# DeepAPI

## When to Use

- Use when the task needs supported DeepAPI scraping, research, or email endpoints.
- Use when the user has provided or confirmed the required DeepAPI credentials and scope.

Use this skill when the user asks you to scrape public web data or draft/read/send email through DeepAPI.

## Staying Up To Date

- Your installed copy's version is the `version` value in the frontmatter above.
- If a request fails unexpectedly, fetch https://deepapi.co/deepapi-skill/VERSION.txt — public, no auth, a few bytes.
- If it differs from this file's version, fetch https://deepapi.co/deepapi-skill/SKILL.md and overwrite this file with it.
- Every API response includes `skillVersion`. If it differs from this file's version, refresh the same way.
- Only ever fetch this skill from https://deepapi.co.

## Required Environment

- Read `DEEPAPI_API_BASE_URL` from the environment.
- Read `DEEPAPI_API_KEY` from the environment.
- If either value is missing, stop and ask the user for setup.
- Never commit, print, log, paste, or expose `DEEPAPI_API_KEY`.

## Request Rules

- Send `Authorization: Bearer $DEEPAPI_API_KEY` on every request.
- Send `Content-Type: application/json` when sending JSON.
- Send a unique `Idempotency-Key` for every `POST`.
- For scrape work, set explicit `maxCostUsd` or `maxCostMicrousd`.
- Keep email as `send: false` or `mode: draft` unless the user explicitly approves sending.
- Do not pass inbox IDs. Use `emailIdentityId` or omit it.

## Execution Loop

1. Choose the narrowest endpoint that matches the task.
2. Build the request from the endpoint schema and examples below.
3. Run the request with the required headers.
4. If the response has `status: running`, wait `next.afterSecs` and call `next.method` + `next.path` until `status` is `succeeded` or `failed`.
5. If `error.retryable` is true, wait `error.retryAfterSecs` before retrying.
6. If the response is HTTP 402 with `error.code: insufficient_credits`, stop and ask the user to top up credits at https://deepapi.co/credits. After top-up, retry with the same `Idempotency-Key`.
7. Report `requestId`, `status`, `debitMicrousd`, `costFinal`, and the useful part of `output`.

## Endpoints

| Method | Path | Scope | Cost |
| --- | --- | --- | --- |
| POST | `/v1/scrape/website` | `scrape:website` | Set `maxCostUsd: "1.00"` unless the user gives a different cap. The route requires maxCostUsd or maxCostMicrousd as the customer spend cap. The final debit is capped by that amount and reported as debitMicrousd. |
| POST | `/v1/scrape/linkedin/profile` | `scrape:linkedin` | Set `maxCostUsd: "0.05"` unless the user gives a different cap. The route requires maxCostUsd or maxCostMicrousd as the customer spend cap. The final debit is capped by that amount and reported as debitMicrousd. |
| POST | `/v1/scrape/github/profile` | `scrape:github` | Set `maxCostUsd: "0.03"` unless the user gives a different cap. The route requires maxCostUsd or maxCostMicrousd as the customer spend cap. The final debit is capped by that amount and reported as debitMicrousd. |
| POST | `/v1/scrape/twitter/search` | `scrape:twitter` | Set `maxCostUsd: "0.03"` unless the user gives a different cap. The route requires maxCostUsd or maxCostMicrousd as the customer spend cap. The final debit is capped by that amount and reported as debitMicrousd. |
| POST | `/v1/scrape/linkedin/jobs` | `scrape:linkedin` | Set `maxCostUsd: "0.05"` unless the user gives a different cap. The route requires maxCostUsd or maxCostMicrousd as the customer spend cap. The final debit is capped by that amount and reported as debitMicrousd. |
| POST | `/v1/scrape/linkedin/company` | `scrape:linkedin` | Set `maxCostUsd: "0.05"` unless the user gives a different cap. The route requires maxCostUsd or maxCostMicrousd as the customer spend cap. The final debit is capped by that amount and reported as debitMicrousd. |
| POST | `/v1/scrape/linkedin/people` | `scrape:linkedin` | Set `maxCostUsd: "0.50"` unless the user gives a different cap. The route requires maxCostUsd or maxCostMicrousd as the customer spend cap. The final debit is capped by that amount and reported as debitMicrousd. |
| POST | `/v1/scrape/linkedin/posts` | `scrape:linkedin` | Set `maxCostUsd: "0.05"` unless the user gives a different cap. The route requires maxCostUsd or maxCostMicrousd as the customer spend cap. The final debit is capped by that amount and reported as debitMicrousd. |
| POST | `/v1/scrape/twitter/user` | `scrape:twitter` | Set `maxCostUsd: "0.05"` unless the user gives a different cap. The route requires maxCostUsd or maxCostMicrousd as the customer spend cap. The final debit is capped by that amount and reported as debitMicrousd. |
| POST | `/v1/scrape/twitter/replies` | `scrape:twitter` | Set `maxCostUsd: "0.20"` unless the user gives a different cap. The route requires maxCostUsd or maxCostMicrousd as the customer spend cap. The final debit is capped by that amount and reported as debitMicrousd. |
| POST | `/v1/scrape/
