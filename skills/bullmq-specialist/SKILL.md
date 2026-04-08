---
name: bullmq-specialist
description: BullMQ expert for Redis-backed job queues, background processing, and reliable async execution in Node.js/TypeScript applications. 
category: AI & Agents
source: antigravity
tags: [typescript, node, nextjs, api, ai, llm, automation, workflow, kubernetes, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/bullmq-specialist
---


# BullMQ Specialist

BullMQ expert for Redis-backed job queues, background processing, and
reliable async execution in Node.js/TypeScript applications.

## Principles

- Jobs are fire-and-forget from the producer side - let the queue handle delivery
- Always set explicit job options - defaults rarely match your use case
- Idempotency is your responsibility - jobs may run more than once
- Backoff strategies prevent thundering herds - exponential beats linear
- Dead letter queues are not optional - failed jobs need a home
- Concurrency limits protect downstream services - start conservative
- Job data should be small - pass IDs, not payloads
- Graceful shutdown prevents orphaned jobs - handle SIGTERM properly

## Capabilities

- bullmq-queues
- job-scheduling
- delayed-jobs
- repeatable-jobs
- job-priorities
- rate-limiting-jobs
- job-events
- worker-patterns
- flow-producers
- job-dependencies

## Scope

- redis-infrastructure -> redis-specialist
- serverless-queues -> upstash-qstash
- workflow-orchestration -> temporal-craftsman
- event-sourcing -> event-architect
- email-delivery -> email-systems

## Tooling

### Core

- bullmq
- ioredis

### Hosting

- upstash
- redis-cloud
- elasticache
- railway

### Monitoring

- bull-board
- arena
- bullmq-pro

### Patterns

- delayed-jobs
- repeatable-jobs
- job-flows
- rate-limiting
- sandboxed-processors

## Patterns

### Basic Queue Setup

Production-ready BullMQ queue with proper configuration

**When to use**: Starting any new queue implementation

import { Queue, Worker, QueueEvents } from 'bullmq';
import IORedis from 'ioredis';

// Shared connection for all queues
const connection = new IORedis(process.env.REDIS_URL, {
  maxRetriesPerRequest: null,  // Required for BullMQ
  enableReadyCheck: false,
});

// Create queue with sensible defaults
const emailQueue = new Queue('emails', {
  connection,
  defaultJobOptions: {
    attempts: 3,
    backoff: {
      type: 'exponential',
      delay: 1000,
    },
    removeOnComplete: { count: 1000 },
    removeOnFail: { count: 5000 },
  },
});

// Worker with concurrency limit
const worker = new Worker('emails', async (job) => {
  await sendEmail(job.data);
}, {
  connection,
  concurrency: 5,
  limiter: {
    max: 100,
    duration: 60000,  // 100 jobs per minute
  },
});

// Handle events
worker.on('failed', (job, err) => {
  console.error(`Job ${job?.id} failed:`, err);
});

### Delayed and Scheduled Jobs

Jobs that run at specific times or after delays

**When to use**: Scheduling future tasks, reminders, or timed actions

// Delayed job - runs once after delay
await queue.add('reminder', { userId: 123 }, {
  delay: 24 * 60 * 60 * 1000,  // 24 hours
});

// Repeatable job - runs on schedule
await queue.add('daily-digest', { type: 'summary' }, {
  repeat: {
    pattern: '0 9 * * *',  // Every day at 9am
    tz: 'America/New_York',
  },
});

// Remove repeatable job
await queue.removeRepeatable('daily-digest', {
  pattern: '0 9 * * *',
  tz: 'America/New_York',
});

### Job Flows and Dependencies

Complex multi-step job processing with parent-child relationships

**When to use**: Jobs depend on other jobs completing first

import { FlowProducer } from 'bullmq';

const flowProducer = new FlowProducer({ connection });

// Parent waits for all children to complete
await flowProducer.add({
  name: 'process-order',
  queueName: 'orders',
  data: { orderId: 123 },
  children: [
    {
      name: 'validate-inventory',
      queueName: 'inventory',
      data: { orderId: 123 },
    },
    {
      name: 'charge-payment',
      queueName: 'payments',
      data: { orderId: 123 },
    },
    {
      name: 'notify-warehouse',
      queueName: 'notifications',
      data: { orderId: 123 },
    },
  ],
});

### Graceful Shutdown

Properly close workers without losing jobs

**When to use**: Deploying or restarting workers

const shutdown = async () => {
  console.log('Shutting down gracefully...');

  // Stop accepting new jobs
  await worker.pause();

  // Wait for current jobs to finish (with timeout)
  await worker.close();

  // Close queue connection
  await queue.close();

  process.exit(0);
};

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

### Bull Board Dashboard

Visual monitoring for BullMQ queues

**When to use**: Need visibility into queue status and job states

import { createBullBoard } from '@bull-board/api';
import { BullMQAdapter } from '@bull-board/api/bullMQAdapter';
import { ExpressAdapter } from '@bull-board/express';

const serverAdapter = new ExpressAdapter();
serverAdapter.setBasePath('/admin/queues');

createBullBoard({
  queues: [
    new BullMQAdapter(emailQueue),
    new BullMQAdapter(orderQueue),
  ],
  serverAdapter,
});

app.use('/admin/queues', serverAdapter.getRouter());

## Validation Checks

### Redis connection missing maxRetriesPerRequest

Severity: ERROR

BullMQ requires maxRetriesPerRequest null for proper reconnection handling

Message: BullMQ queue/worker created without 
