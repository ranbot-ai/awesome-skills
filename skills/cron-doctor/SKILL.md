---
name: cron-doctor
description: Diagnose and validate cron expressions before they ship. Catches the five silent death-traps: impossible dates that never fire, OR-semantics that fire too often, midnight spikes, uneven step drift, an
category: Document Processing
source: antigravity
tags: [javascript, node, claude, ai, agent, security, docker, kubernetes, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/cron-doctor
---


# cron-doctor

## Overview

Cron is deceptively error-prone. The failure mode is **silent** — a syntactically
valid expression that simply never fires, or fires far more often than intended.
`0 0 30 2 *` parses cleanly and then sits dead forever (February has no 30th).
`0 0 1,15 * 1` looks like "1st and 15th if Monday" but actually means "1st, 15th,
**OR** every Monday" — ~6 fires/month instead of ~2.

This skill teaches an agent to catch those before they reach production. It comes
with a zero-dependency validation engine (`scripts/cron-engine.js`, no install
needed) that parses, describes, deep-validates, and computes next fire times.

## When to Use This Skill

- Use when a user writes, edits, reviews, or deploys a cron expression — in a
  crontab, a Kubernetes `CronJob`, a GitHub Actions `schedule`, an Airflow DAG,
  a Celery beat schedule, a systemd timer, or any scheduled task.
- Use when debugging a job that "didn't fire" or "fired at the wrong time."
- Use when a user asks "what does this cron expression mean?" or "when will this
  run next?" or "how often does this run per year?"
- Use when reviewing a CI/CD pipeline or infrastructure config that contains a
  `schedule` field.
- Use when a user pastes a 5-field cron expression and asks for a sanity check.

## How It Works

### Step 1: Parse the expression

Split on whitespace into 5 fields: minute, hour, day-of-month, month, day-of-week.
Confirm valid ranges:

| Field | Position | Range | Notes |
|-------|----------|-------|-------|
| minute | 1 | 0–59 | |
| hour | 2 | 0–23 | |
| day-of-month | 3 | 1–31 | |
| month | 4 | 1–12 | names (JAN–DEC) accepted |
| day-of-week | 5 | 0–7 | 0 and 7 both = Sunday; names (SUN–SAT) accepted |

### Step 2: Describe it in plain English

State what the user *thinks* it does vs. what it *actually* does. Be explicit
about OR-vs-AND semantics for day-of-month + day-of-week (see death-trap #2).

### Step 3: Run the trap checklist

Check the five death-traps below and flag any that apply.

### Step 4: Calculate next runs and annual fire count

Compute the next 5 fire times as concrete dates so the user can verify the
schedule behaves as expected. Estimate annual fire count — a schedule that fires
365×/year vs. 12×/year is a ~30× cost and load difference.

## The Five Cron Death-Traps

These are the bugs that pass `crontab -l` validation but break in production.

### 1. Impossible dates — the "never fires" bug

```
0 0 30 2 *
```

**Valid syntax. Never fires.** February has no 30th. This schedule is a dead job
that silently sits forever. The same applies to day 31 in any 30-day month:
`0 0 31 4 *`, `0 0 31 6 *`, `0 0 31 9 *`, `0 0 31 11 *`.

**Fix:** use `0 0 28-31 * *` and check for end-of-month in the script, or use `L`
(last day) syntax if your scheduler supports it.

### 2. OR-semantics — the "fires too often" bug

```
0 0 1,15 * 1
```

**Does NOT mean** "midnight on the 1st and 15th if it's Monday."
**Does mean** "midnight on the 1st, the 15th, **OR** every Monday." That's ~6
fires/month instead of ~2.

This is the single most misunderstood cron rule. When **both** day-of-month AND
day-of-week are restricted (neither is `*`), cron uses OR logic, not AND.

**Fix:** if you need "1st and 15th only if Monday," run daily and check in the
script:

```bash
0 0 * * 1 [ "$(date +%d)" = "01" -o "$(date +%d)" = "15" ] && your-command
```

### 3. Midnight spike — the "everything at once" bug

```
0 0 * * *
```

Every job scheduled at `0 0` competes for resources at exactly 00:00. Database
backups, log rotations, cert renewals, report generation — all fire simultaneously.
This causes load spikes, connection-pool exhaustion, and cascading timeouts.

**Fix:** stagger jobs across the hour. Use `17 2 * * *` or `43 3 * * *` instead of
`0 0`. Jitter is your friend.

### 4. Uneven steps — the "drift" bug

```
*/7 * * * *
```

**Does NOT mean** "every 7 minutes evenly." It means "every 7 minutes starting at
0, then resets at 60." So: 0, 7, 14, 21, 28, 35, 42, 49, 56 — then 0 again
(a 4-minute gap). The intervals drift: 7,7,7,7,7,7,7,7,**4**.

**Fix:** 60 is not divisible by 7. Use step values that divide 60 evenly: `*/5`,
`*/10`, `*/15`, `*/20`, `*/30`. If you truly need every-7-minutes, use a loop with
`sleep 420`.

### 5. Leap-year February 29 — the "annual surprise"

```
0 0 29 2 *
```

Fires only on leap years — February 29, 2024 / 2028 / 2032… If someone writes this
expecting "end of February," they'll be confused for 3 out of every 4 years.

**Fix:** use `0 0 28 2 *` and handle the 29th case in the script if needed.

## Using the validation script

This skill ships a zero-dependency engine at `scripts/cron-engine.js` (Node.js, no
`npm install` needed). You can use it programmatically or from the CLI:

```javascript
// Programmatic — Node.js, zero dependencies
const { describe, validate, nextRuns, formatNextRuns } = require('./scripts/cron-engine.js');

// Parse + describe -> returns { text, error, parsed }
const d = describe('0 0
