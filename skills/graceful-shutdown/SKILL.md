---
name: graceful-shutdown
description: Implement graceful shutdown for servers and workers: drain connections, finish in-flight work, release resources, and exit cleanly on SIGTERM/SIGINT. 
category: AI & Agents
source: antigravity
tags: [python, typescript, node, api, claude, ai, template, docker, kubernetes]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/graceful-shutdown
---


# Graceful Shutdown

## Overview

A skill for implementing graceful shutdown in servers, workers, and long-running processes. Ensures in-flight requests complete, background jobs finish or checkpoint, database connections close cleanly, and the process exits with a proper status code. Essential for zero-downtime deployments in container orchestrators (Kubernetes, ECS, Docker Compose) and bare-metal process managers (systemd, PM2).

## When to Use This Skill

- Use when building an HTTP server that must not drop active connections during deploys
- Use when writing a background worker that processes jobs from a queue
- Use when deploying to Kubernetes, Docker, or any environment that sends SIGTERM before killing
- Use when the user says "graceful shutdown", "drain connections", "handle SIGTERM", "zero downtime", or "don't kill active requests"
- Use when implementing health check endpoints (`/healthz`, `/readyz`) for orchestrators

## How It Works

### Step 1: Register signal handlers early

Trap `SIGTERM` (orchestrator shutdown) and `SIGINT` (Ctrl+C) at process startup. Set a flag so the application knows it is shutting down.

```typescript
let isShuttingDown = false;

function onShutdownSignal(signal: string): void {
  if (isShuttingDown) return; // prevent double-shutdown
  isShuttingDown = true;
  console.log(`Received ${signal}, starting graceful shutdown...`);
  shutdown();
}

process.on("SIGTERM", () => onShutdownSignal("SIGTERM"));
process.on("SIGINT", () => onShutdownSignal("SIGINT"));
```

### Step 2: Stop accepting new work

Immediately stop the server from accepting new connections. For HTTP servers, call `server.close()`. For queue workers, stop polling for new jobs.

```typescript
async function shutdown(): Promise<void> {
  // 1. Stop accepting new connections
  server.close(() => {
    console.log("Server closed — no new connections accepted");
  });

  // 2. Mark health check as not-ready so load balancers stop routing
  //    (readiness probe returns 503 from this point)
}
```

### Step 3: Drain in-flight work with a deadline

Wait for active requests and background tasks to finish, but enforce a hard deadline so the process never hangs indefinitely.

```typescript
const DRAIN_TIMEOUT_MS = 25_000; // must be less than orchestrator's terminationGracePeriodSeconds

async function drainAndExit(): Promise<void> {
  const deadline = setTimeout(() => {
    console.error("Drain timeout reached — forcing exit");
    process.exit(1);
  }, DRAIN_TIMEOUT_MS);
  deadline.unref(); // don't keep the event loop alive just for the timer

  try {
    // Wait for active connections to finish
    await waitForActiveConnections();

    // Flush buffered data (logs, metrics, queues)
    await flushBuffers();

    // Close external resource handles
    await closeResources();

    console.log("Graceful shutdown complete");
    process.exit(0);
  } catch (err) {
    console.error("Error during shutdown:", err);
    process.exit(1);
  }
}
```

### Step 4: Implement readiness and liveness probes

Orchestrators use these to decide whether to route traffic and whether to restart the container.

```typescript
import { createServer, IncomingMessage, ServerResponse } from "node:http";

function handleHealthCheck(req: IncomingMessage, res: ServerResponse): void {
  if (req.url === "/healthz") {
    // Liveness: is the process alive and not deadlocked?
    res.writeHead(200).end("ok");
    return;
  }

  if (req.url === "/readyz") {
    // Readiness: should traffic be routed here?
    if (isShuttingDown) {
      res.writeHead(503).end("shutting down");
    } else {
      res.writeHead(200).end("ready");
    }
    return;
  }
}
```

### Step 5: Track active connections

Maintain a count of in-flight requests so you know when draining is complete.

```typescript
let activeConnections = 0;
let drainResolve: (() => void) | null = null;

function onRequestStart(): void {
  activeConnections++;
}

function onRequestEnd(): void {
  activeConnections--;
  if (isShuttingDown && activeConnections === 0 && drainResolve) {
    drainResolve();
  }
}

function waitForActiveConnections(): Promise<void> {
  if (activeConnections === 0) return Promise.resolve();
  return new Promise((resolve) => {
    drainResolve = resolve;
  });
}
```

## Examples

### Example 1: Express.js server with graceful shutdown

```typescript
import express from "express";
import { createServer } from "node:http";

const app = express();
const server = createServer(app);
let isShuttingDown = false;
let activeRequests = 0;

// Track in-flight requests
app.use((req, res, next) => {
  if (isShuttingDown) {
    res.setHeader("Connection", "close");
    res.status(503).json({ error: "Server is shutting down" });
    return;
  }
  activeRequests++;
  res.on("finish", () => activeRequests--);
  next();
});

// Health endpoints
app.get("/healthz", (_, res) => res.send("ok"));
app.get("/readyz", (_, res) => {
  res.status(isShuttingDown ? 503 : 200).send(isShuttingDown 
