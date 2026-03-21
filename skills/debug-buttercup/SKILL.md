---
name: debug-buttercup
description: All pods run in namespace crs. Use when pods in the crs namespace are in CrashLoopBackOff, OOMKilled, or restarting, multiple services restart simultaneously (cascade failure), or redis is unresponsiv
category: AI & Agents
source: antigravity
tags: [node, api, ai, llm, workflow, template, docker, kubernetes, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/debug-buttercup
---


# Debug Buttercup

## When to Use
- Pods in the `crs` namespace are in CrashLoopBackOff, OOMKilled, or restarting
- Multiple services restart simultaneously (cascade failure)
- Redis is unresponsive or showing AOF warnings
- Queues are growing but tasks are not progressing
- Nodes show DiskPressure, MemoryPressure, or PID pressure
- Build-bot cannot reach the Docker daemon (DinD failures)
- Scheduler is stuck and not advancing task state
- Health check probes are failing unexpectedly
- Deployed Helm values don't match actual pod configuration

## When NOT to Use

- Deploying or upgrading Buttercup (use Helm and deployment guides)
- Debugging issues outside the `crs` Kubernetes namespace
- Performance tuning that doesn't involve a failure symptom

## Namespace and Services

All pods run in namespace `crs`. Key services:

| Layer | Services |
|-------|----------|
| Infra | redis, dind, litellm, registry-cache |
| Orchestration | scheduler, task-server, task-downloader, scratch-cleaner |
| Fuzzing | build-bot, fuzzer-bot, coverage-bot, tracer-bot, merger-bot |
| Analysis | patcher, seed-gen, program-model, pov-reproducer |
| Interface | competition-api, ui |

## Triage Workflow

Always start with triage. Run these three commands first:

```bash
# 1. Pod status - look for restarts, CrashLoopBackOff, OOMKilled
kubectl get pods -n crs -o wide

# 2. Events - the timeline of what went wrong
kubectl get events -n crs --sort-by='.lastTimestamp'

# 3. Warnings only - filter the noise
kubectl get events -n crs --field-selector type=Warning --sort-by='.lastTimestamp'
```

Then narrow down:

```bash
# Why did a specific pod restart? Check Last State Reason (OOMKilled, Error, Completed)
kubectl describe pod -n crs <pod-name> | grep -A8 'Last State:'

# Check actual resource limits vs intended
kubectl get pod -n crs <pod-name> -o jsonpath='{.spec.containers[0].resources}'

# Crashed container's logs (--previous = the container that died)
kubectl logs -n crs <pod-name> --previous --tail=200

# Current logs
kubectl logs -n crs <pod-name> --tail=200
```

### Historical vs Ongoing Issues

High restart counts don't necessarily mean an issue is ongoing -- restarts accumulate over a pod's lifetime. Always distinguish:
- `--tail` shows the end of the log buffer, which may contain old messages. Use `--since=300s` to confirm issues are actively happening now.
- `--timestamps` on log output helps correlate events across services.
- Check `Last State` timestamps in `describe pod` to see when the most recent crash actually occurred.

### Cascade Detection

When many pods restart around the same time, check for a shared-dependency failure before investigating individual pods. The most common cascade: Redis goes down -> every service gets `ConnectionError`/`ConnectionRefusedError` -> mass restarts. Look for the same error across multiple `--previous` logs -- if they all say `redis.exceptions.ConnectionError`, debug Redis, not the individual services.

## Log Analysis

```bash
# All replicas of a service at once
kubectl logs -n crs -l app=fuzzer-bot --tail=100 --prefix

# Stream live
kubectl logs -n crs -l app.kubernetes.io/name=redis -f

# Collect all logs to disk (existing script)
bash deployment/collect-logs.sh
```

## Resource Pressure

```bash
# Per-pod CPU/memory
kubectl top pods -n crs

# Node-level
kubectl top nodes

# Node conditions (disk pressure, memory pressure, PID pressure)
kubectl describe node <node> | grep -A5 Conditions

# Disk usage inside a pod
kubectl exec -n crs <pod> -- df -h

# What's eating disk
kubectl exec -n crs <pod> -- sh -c 'du -sh /corpus/* 2>/dev/null'
kubectl exec -n crs <pod> -- sh -c 'du -sh /scratch/* 2>/dev/null'
```

## Redis Debugging

Redis is the backbone. When it goes down, everything cascades.

```bash
# Redis pod status
kubectl get pods -n crs -l app.kubernetes.io/name=redis

# Redis logs (AOF warnings, OOM, connection issues)
kubectl logs -n crs -l app.kubernetes.io/name=redis --tail=200

# Connect to Redis CLI
kubectl exec -n crs <redis-pod> -- redis-cli

# Inside redis-cli: key diagnostics
INFO memory          # used_memory_human, maxmemory
INFO persistence     # aof_enabled, aof_last_bgrewrite_status, aof_delayed_fsync
INFO clients         # connected_clients, blocked_clients
INFO stats           # total_connections_received, rejected_connections
CLIENT LIST          # see who's connected
DBSIZE               # total keys

# AOF configuration
CONFIG GET appendonly     # is AOF enabled?
CONFIG GET appendfsync   # fsync policy: everysec, always, or no

# What is /data mounted on? (disk vs tmpfs matters for AOF performance)
```

```bash
kubectl exec -n crs <redis-pod> -- mount | grep /data
kubectl exec -n crs <redis-pod> -- du -sh /data/
```

### Queue Inspection

Buttercup uses Redis streams with consumer groups. Queue names:

| Queue | Stream Key |
|-------|-----------|
| Build | fuzzer_build_queue |
| Build Output | fuzzer_build_output_queue |
| Crash | fuzzer_crash_queue |
| Confirmed Vu
