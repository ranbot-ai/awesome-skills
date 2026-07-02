---
name: eas-update-insights
description: Check the health of published EAS Updates: crash rates, install/launch counts, unique users, payload size, and the split between embedded and OTA users per channel. Use when the user asks how an updat
category: AI & Agents
source: antigravity
tags: [ai, workflow, design, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/eas-update-insights
---


# EAS Update Insights

Query the health of published EAS Updates directly from the CLI: launches, failed launches, crash rates, unique users, payload size, the embedded-vs-OTA user split per channel, and the most popular updates per runtime version. The data is the same data that powers the update and channel detail pages on expo.dev; these commands expose it in the terminal in human and JSON form.

## When to use this skill

Use this when the user wants to assess the health or adoption of a published EAS Update: crash rates, install counts, unique users, bundle size, or the split between embedded and OTA users on a channel.

Example prompts:

- "How is the latest update doing?"
- "Is the latest update healthy?"
- "Is the new release crashing more than the last one?"
- "How many users are on the latest update vs the embedded build?"
- "Which update is most popular on production right now?"
- "How big is our update bundle?"

Also fits: post-publish rollout monitoring and regression detection.

Don't use when the user needs per-user crash detail or device-level reporting; this skill only exposes aggregate EAS metrics.

## Prerequisites

- `eas-cli` installed (`npm install -g eas-cli`).
- Logged in: `eas login`.
- For `channel:insights`: run from an Expo project directory (the command resolves the project ID from `app.json`). `update:insights` only needs a login.

## Commands at a glance

| Command | Purpose |
|---|---|
| `eas update:list` | Discover recent update groups, their `group` IDs, and branch names |
| `eas update:insights <groupId>` | Per-platform launches, failed launches, crash rate, unique users, payload size, daily breakdown |
| `eas update:view <groupId> --insights` | Update group details + the same metrics appended |
| `eas channel:insights --channel <name> --runtime-version <version>` | Embedded/OTA user counts, most popular updates, cumulative metrics for a channel + runtime |

All of these support `--json --non-interactive` for programmatic parsing.

## Discovering IDs

Before querying insights for an update group, you need its `group` ID. Use `eas update:list` with either `--branch <name>` (updates on that branch) or `--all` (updates across all branches). Always pass `--json --non-interactive` when running non-interactively; without a branch/`--all` flag the command will otherwise prompt for a branch selection:

```bash
# Latest group id across all branches
eas update:list --all --json --non-interactive | jq -r '.currentPage[0].group'

# Latest group id on a specific branch
eas update:list --branch production --json --non-interactive | jq -r '.currentPage[0].group'
```

The JSON response has a `currentPage` array with one entry per update group (both platforms of the same publish are collapsed into one entry):

```json
{
  "currentPage": [
    {
      "branch": "production",
      "message": "\"Fix checkout crash\" (1 week ago by someone)",
      "runtimeVersion": "1.0.6",
      "group": "03d5dfcf-736c-475a-8730-af039c3f4d06",
      "platforms": "android, ios",
      "isRollBackToEmbedded": false
    }
  ]
}
```

Entries also carry `codeSigningKey` and `rolloutPercentage`, but only when those features are in use for the group (undefined values are omitted from the JSON output).

When called with `--branch <name>`, the response also includes `name` (the branch name) and `id` (the branch ID) at the top level.

## `eas update:insights <groupId>`

Shows launches, failed launches, crash rate, unique users, launch asset count, and average payload size for a single update group, broken down **per platform** (iOS, Android), plus a daily breakdown of launches and failures.

### Basic use

```bash
eas update:insights 03d5dfcf-736c-475a-8730-af039c3f4d06
```

### Flags

| Flag | Description |
|---|---|
| `--days <N>` | Look back N days. Default: **7**. Mutually exclusive with `--start`/`--end`. |
| `--start <iso-date>` / `--end <iso-date>` | Explicit time range, e.g. `--start 2026-04-01 --end 2026-04-15`. |
| `--platform <ios\|android>` | Filter to a single platform. Omit to see all platforms in the group. |
| `--json` | Machine-readable output. Implies `--non-interactive`. |
| `--non-interactive` | Required when scripting. |

### JSON output shape

Top level: `groupId`, `timespan` (`start`, `end`, `daysBack`), and `platforms[]` with one entry per platform the group was published to. Each platform entry has `updateId`, `totals` (`uniqueUsers`, `installs`, `failedInstalls`, `crashRatePercent`), `payload` (`launchAssetCount`, `averageUpdatePayloadBytes`), and a `daily[]` time series of `{ date, installs, failedInstalls }`.

For the complete schema and field reference, see [references/update-insights-schema.md](./references/update-insights-schema.md).

Fields that matter for health assessment:

- `platforms[].totals.crashRatePercent`, computed as `failedInstalls / (installs + failedInstalls) * 100`. Zero when there are no installs.
- `platforms[].totals.installs` and `uniqueUsers` give the adoption sign
