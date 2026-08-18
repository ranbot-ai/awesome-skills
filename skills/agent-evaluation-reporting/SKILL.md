---
name: agent-evaluation-reporting
description: Use when summarizing agent evaluations where autonomous, assisted, failed, timed-out, or invalid outcomes must remain distinct and comparable. 
category: AI & Agents
source: antigravity
tags: [claude, ai, agent, workflow, design, security, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/agent-evaluation-reporting
---


# Agent Evaluation Reporting

## Overview

Turn raw agent evaluation runs into a decision-ready report without hiding failures or overstating capability. Keep outcome populations, denominators, latency populations, and experiment conditions explicit so readers can reproduce every headline number.

## When to Use This Skill

- Use when reporting benchmark, regression, pilot, or production evaluation runs for an AI agent.
- Use when autonomous and human-assisted completions appear in the same result set.
- Use when failures, timeouts, infrastructure-invalid runs, retries, or partial results affect the denominator.
- Use when comparing two agents, prompts, harnesses, or releases and deciding whether the comparison is valid.

## How It Works

### Step 1: Freeze the comparison contract

Record the task set and sampling, model and provider, prompt or policy version, tool and harness versions, evaluator rubric, timeout and retry policy, token or cost budget, environment, and human-intervention policy. Assign the configuration a stable label or digest.

If a material condition differs between runs, mark the comparison as non-equivalent. Report a directional observation only; do not claim that the changed agent caused the difference.

### Step 2: Build a mutually exclusive outcome ledger

Classify every scheduled attempt exactly once:

| Outcome | Meaning |
|---|---|
| `autonomous_success` | The agent satisfied the evaluator without human intervention. |
| `assisted_success` | The task succeeded only after a human intervened. |
| `failure` | The run reached a terminal, evaluable failure. |
| `timeout` | The run exhausted its declared time or step budget. |
| `invalid` | The agent never received a valid evaluation because the harness, environment, or input failed. |

Preserve attempt ID, task ID or seed, retry index, parent attempt ID, configuration label, outcome, intervention count, duration, cost, evaluator evidence, and invalid reason when available. Never silently drop invalid or retried runs.

Also build a unique-task rollup. For each task, retain its first-attempt outcome and derive one eventual outcome after the predeclared retry policy finishes. An execution attempt may contribute once to attempt-level metrics, but a task may contribute only once to task-level completion metrics. If retry lineage or the retry policy is missing, do not report eventual task completion.

### Step 3: Lock each metric to a denominator

Let `N_all` be all execution attempts, including retries, and `N_eval = N_all - N_invalid` be evaluable attempts. Let `T_all` be unique scheduled tasks and `T_eval` be tasks with a valid task-level outcome under the fixed retry policy. Report counts beside every rate.

```text
autonomous attempt success = N_autonomous / N_eval
assisted attempt success   = N_assisted / N_eval
attempt non-completion     = (N_failure + N_timeout) / N_eval
invalid-attempt rate       = N_invalid / N_all
first-attempt completion   = T_first_attempt_completed / T_all
eventual task completion   = T_eventual_completed / T_eval
operational task delivery  = T_eventual_completed / T_all
```

Label attempt-level and unique-task metrics explicitly; never call an attempt-level rate workflow completion. Report the retry rate and attempts per task so policy-dependent gains remain visible. Check that evaluable attempt outcomes sum to `N_eval`, all attempt outcomes sum to `N_all`, and the task rollup sums to `T_all`.

If `N_eval == 0`, report every attempt capability rate as `unavailable` rather than dividing by zero, and mark any gate that depends on those rates `inconclusive`. Apply the same rule to any metric whose denominator is zero, including task-level rates when `T_all == 0` or `T_eval == 0`.

### Step 4: Keep latency and cost populations honest

Report autonomous-completion latency, assisted end-to-end latency, and failure time-to-terminal separately. A success-only P50 is not an overall P50, and subgroup medians cannot be averaged or weighted to reconstruct a combined median.

Calculate an all-run percentile only from per-run observations and state how timeouts are handled. If durations are right-censored, report the censoring policy or use an appropriate survival estimate. Apply the same population labels to token and cost metrics.

### Step 5: Quantify uncertainty and comparability

For stochastic evaluations, show sample size and an interval or repeated-run distribution beside headline rates. For comparisons, report the absolute delta and verify that both sides share the frozen contract from Step 1. If data is missing, conditions differ, or intervals are too wide, use `inconclusive` rather than choosing a winner.

### Step 6: Map evidence to predeclared decision gates

Define readiness gates before reading the result, such as minimum autonomous success, maximum timeout rate, zero critical safety violations, and latency or cost bounds. Return `pass`, `fail`, or `inconclusive` for each gate.

Do not infer production readi
