---
name: brendangregg-use-tsa
description: Methodical performance troubleshooting and root-cause analysis with Brendan Gregg's USE and TSA methods, plus evidence-backed RCA and postmortem reports. 
category: AI & Agents
source: antigravity
tags: [pdf, api, claude, ai, agent, workflow, template, security, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/brendangregg-use-tsa
---


# Brendan Gregg USE+TSA Performance Analysis

## Overview

A fixed, evidence-first procedure for system performance debugging, root-cause analysis (RCA), and incident reporting, distilled from Brendan Gregg's published methodologies. Instead of running whichever commands happen to be familiar, the agent poses questions first and then finds metrics to answer them: the USE Method (Utilization, Saturation, Errors) sweeps every resource, the TSA Method (Thread State Analysis) decomposes thread time, and off-CPU analysis plus flame graphs drill into what the sweeps find. Every investigation ends in a structured triage note, RCA report, or postmortem where each claim traces to a command and its output.

This skill adapts material from the community repository
[thecsdoctor/brendangregg-use-tsa-skill](https://github.com/thecsdoctor/brendangregg-use-tsa-skill)
(full checklists, reference library, and report templates live there).

## When to Use This Skill

- Use when a server, VM, or container is "slow" and the cause is unknown
- Use when latency or throughput regressed after a deploy, config change, or load shift
- Use when CPU, memory, disk, or network metrics look abnormal and need interpretation
- Use when an application hangs or threads pile up
- Use when the user asks for debugging, triage, or root-cause analysis of a performance issue
- Use when an incident needs an RCA report or a blameless postmortem with an evidence trail

## How It Works

### Step 0: Problem Statement

Define the problem before measuring. Ask: What makes you think there is a problem? Has it ever performed well? What changed recently (software, hardware, load)? Can it be expressed as latency or run time — quantify it. Who else is affected? What is the environment (OS, versions, config, container/VM limits)?

### Step 1: 60-Second Triage (Linux)

Run the ten-command sweep, checking **errors and saturation first** (easiest to interpret), then utilization. Record every exonerated resource.

```bash
uptime                 # load trend (includes uninterruptible I/O on Linux)
dmesg | tail           # kernel errors: oom-killer, SYN flooding, hardware
vmstat 1               # r > CPU count = CPU saturation; si/so = swapping; wa = disk
mpstat -P ALL 1        # per-CPU imbalance (single hot CPU = single-threaded app)
pidstat 1              # per-process CPU over time
iostat -xz 1           # await (app-suffered latency), avgqu-sz, %util
free -m                # memory; buffers/cache near zero hurts
sar -n DEV 1           # NIC throughput vs link limit
sar -n TCP,ETCP 1      # active/passive connections, retransmits
top                    # spot variable load
```

### Step 2: USE Sweep (resource-oriented)

**For every resource, check Utilization, Saturation, and Errors.** Iterate CPUs, memory capacity, network interfaces, storage I/O and capacity, controllers, interconnects — plus software resources (mutex locks, thread pools, process/file-descriptor capacity) and imposed limits (cgroup quotas, hypervisor caps, ulimits). Check errors before utilization. Interpretations: 100% utilization is usually a bottleneck (confirm via saturation); any non-zero saturation can be a problem; non-zero, still-increasing error counters are worth investigating; and a clean sweep is a result — it narrows the search space.

### Step 3: TSA Sweep (thread-oriented)

**For each thread of interest, split time into: Executing / Runnable / Anonymous Paging / Sleeping / Lock / Idle.** Investigate states from most to least frequent with state-appropriate tools. If more than ~10% of time is Runnable or Anonymous Paging, fix those first — latency states can be tuned to zero. Linux instruments: `/proc/PID/schedstat` run_delay and `perf sched latency` (Runnable), `vmstat` si/so and per-process `min_flt` (Paging), `offcputime`/`cpudist` from bcc (Sleeping), `/proc/lock_stat` and `valgrind --tool=drd` (Lock), `pidstat`/flame graphs (Executing).

### Step 4: Drill Down

Follow the biggest contributor: Executing → CPU profile + flame graph; Sleeping/Lock → off-CPU stacks (`offcputime -p PID`, render with `flamegraph.pl --color=io`); latency complaints → time-division decomposition; microservices → RED method (Rate, Errors, Duration). Prefer eBPF in-kernel aggregation over per-event dumps; start with sub-second traces in production.

### Step 5: Confirm Root Cause

State the causal chain (trigger → mechanism → symptom) with every link evidence-backed. Keep falsifiable hypotheses on record even when ruled out. Ask "why" up to five times. Would removing this cause prevent recurrence? Does it explain all primary evidence?

### Step 6: Fix and Verify

Apply the cheapest effective fix (mantra order: don't do it → cache it → do it less → do it later → off-peak → concurrently → cheaper). Re-measure with the **same instruments** as the evidence and show before/after. "Deployed" is not "verified".

### Step 7: Report

Produce the report the situation calls for — triage note, RCA report, or full
