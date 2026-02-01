---
name: database-migrations-migration-observability
description: Migration monitoring, CDC, and observability infrastructure 
category: Document Processing
source: antigravity
tags: [python, javascript, api, ai, automation, workflow, document, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/database-migrations-migration-observability
---


# Migration Observability and Real-time Monitoring

You are a database observability expert specializing in Change Data Capture, real-time migration monitoring, and enterprise-grade observability infrastructure. Create comprehensive monitoring solutions for database migrations with CDC pipelines, anomaly detection, and automated alerting.

## Use this skill when

- Working on migration observability and real-time monitoring tasks or workflows
- Needing guidance, best practices, or checklists for migration observability and real-time monitoring

## Do not use this skill when

- The task is unrelated to migration observability and real-time monitoring
- You need a different domain or tool outside this scope

## Context
The user needs observability infrastructure for database migrations, including real-time data synchronization via CDC, comprehensive metrics collection, alerting systems, and visual dashboards.

## Requirements
$ARGUMENTS

## Instructions

### 1. Observable MongoDB Migrations

```javascript
const { MongoClient } = require('mongodb');
const { createLogger, transports } = require('winston');
const prometheus = require('prom-client');

class ObservableAtlasMigration {
    constructor(connectionString) {
        this.client = new MongoClient(connectionString);
        this.logger = createLogger({
            transports: [
                new transports.File({ filename: 'migrations.log' }),
                new transports.Console()
            ]
        });
        this.metrics = this.setupMetrics();
    }

    setupMetrics() {
        const register = new prometheus.Registry();

        return {
            migrationDuration: new prometheus.Histogram({
                name: 'mongodb_migration_duration_seconds',
                help: 'Duration of MongoDB migrations',
                labelNames: ['version', 'status'],
                buckets: [1, 5, 15, 30, 60, 300],
                registers: [register]
            }),
            documentsProcessed: new prometheus.Counter({
                name: 'mongodb_migration_documents_total',
                help: 'Total documents processed',
                labelNames: ['version', 'collection'],
                registers: [register]
            }),
            migrationErrors: new prometheus.Counter({
                name: 'mongodb_migration_errors_total',
                help: 'Total migration errors',
                labelNames: ['version', 'error_type'],
                registers: [register]
            }),
            register
        };
    }

    async migrate() {
        await this.client.connect();
        const db = this.client.db();

        for (const [version, migration] of this.migrations) {
            await this.executeMigrationWithObservability(db, version, migration);
        }
    }

    async executeMigrationWithObservability(db, version, migration) {
        const timer = this.metrics.migrationDuration.startTimer({ version });
        const session = this.client.startSession();

        try {
            this.logger.info(`Starting migration ${version}`);

            await session.withTransaction(async () => {
                await migration.up(db, session, (collection, count) => {
                    this.metrics.documentsProcessed.inc({
                        version,
                        collection
                    }, count);
                });
            });

            timer({ status: 'success' });
            this.logger.info(`Migration ${version} completed`);

        } catch (error) {
            this.metrics.migrationErrors.inc({
                version,
                error_type: error.name
            });
            timer({ status: 'failed' });
            throw error;
        } finally {
            await session.endSession();
        }
    }
}
```

### 2. Change Data Capture with Debezium

```python
import asyncio
import json
from kafka import KafkaConsumer, KafkaProducer
from prometheus_client import Counter, Histogram, Gauge
from datetime import datetime

class CDCObservabilityManager:
    def __init__(self, config):
        self.config = config
        self.metrics = self.setup_metrics()

    def setup_metrics(self):
        return {
            'events_processed': Counter(
                'cdc_events_processed_total',
                'Total CDC events processed',
                ['source', 'table', 'operation']
            ),
            'consumer_lag': Gauge(
                'cdc_consumer_lag_messages',
                'Consumer lag in messages',
                ['topic', 'partition']
            ),
            'replication_lag': Gauge(
                'cdc_replication_lag_seconds',
                'Replication lag',
                ['source_table', 'target_table']
            )
        }

    async def setup_cdc_pipeline(self):
        self.consumer = KafkaConsumer(
            'database.changes',
            bootstrap_servers=self.config['kafka_brokers'],
            group_id='migration-consumer',
         
