---
name: disaster-recovery
description: Implement disaster recovery strategies and runbooks. Configure RPO/RTO targets and failover procedures. Use when planning for business continuity. 
category: Document Processing
source: antigravity
tags: [markdown, api, ai, agent, automation, template, design, document, security, aws]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/disaster-recovery
---


# Disaster Recovery

Implement disaster recovery strategies including RTO/RPO planning, AWS cross-region failover patterns, DR testing procedures, and automated failover scripts.

## RTO/RPO Planning

```yaml
recovery_metrics:
  RTO:
    definition: "Recovery Time Objective - maximum acceptable downtime"
    measurement: "From incident declaration to service restoration"
    factors:
      - Failover automation maturity
      - Data replication lag
      - DNS propagation time
      - Application warm-up time
      - Verification procedures

  RPO:
    definition: "Recovery Point Objective - maximum acceptable data loss"
    measurement: "Time gap between last good backup and the incident"
    factors:
      - Backup frequency
      - Replication method (sync vs. async)
      - Transaction log shipping interval
      - Cross-region replication lag

service_tier_targets:
  tier_1_critical:
    examples: "Authentication, payment processing, core API"
    rto: "< 15 minutes"
    rpo: "< 1 minute (near-zero)"
    strategy: "Multi-site active-active or warm standby"
    replication: "Synchronous or near-synchronous"
    testing: "Quarterly failover test"

  tier_2_essential:
    examples: "Customer dashboards, reporting, notifications"
    rto: "< 1 hour"
    rpo: "< 15 minutes"
    strategy: "Warm standby or pilot light"
    replication: "Asynchronous with short interval"
    testing: "Semi-annual failover test"

  tier_3_standard:
    examples: "Internal tools, analytics, batch processing"
    rto: "< 4 hours"
    rpo: "< 1 hour"
    strategy: "Pilot light or backup and restore"
    replication: "Periodic snapshots"
    testing: "Annual failover test"

  tier_4_non_essential:
    examples: "Development environments, documentation sites"
    rto: "< 24 hours"
    rpo: "< 24 hours"
    strategy: "Backup and restore"
    replication: "Daily backups"
    testing: "Annual backup restore verification"
```

## DR Strategies Comparison

```yaml
strategies:
  backup_and_restore:
    rto: "Hours"
    rpo: "Hours (depends on backup frequency)"
    cost: "$"
    description: "Regular backups stored in DR region. Restore from backup when needed."
    aws_services:
      - "S3 cross-region replication for backups"
      - "RDS automated snapshots copied to DR region"
      - "AMI copies in DR region"
      - "Terraform/CloudFormation for infrastructure rebuild"
    pros: "Lowest cost, simplest to maintain"
    cons: "Longest recovery time, highest data loss potential"

  pilot_light:
    rto: "Minutes to hours"
    rpo: "Minutes"
    cost: "$$"
    description: "Core infrastructure running in DR region (databases replicated). Scale up compute on failover."
    aws_services:
      - "RDS cross-region read replica (always running)"
      - "S3 cross-region replication"
      - "AMIs pre-built in DR region"
      - "Auto Scaling groups at zero/minimal capacity"
    pros: "Fast database recovery, moderate cost"
    cons: "Compute scale-up adds to recovery time"

  warm_standby:
    rto: "Minutes"
    rpo: "Seconds to minutes"
    cost: "$$$"
    description: "Scaled-down but functional environment in DR region. Scale up on failover."
    aws_services:
      - "RDS cross-region read replica"
      - "ECS/EKS running at reduced capacity"
      - "Route53 health checks for automated DNS failover"
      - "Global Accelerator for traffic management"
    pros: "Fast failover, reduced risk"
    cons: "Higher baseline cost for idle resources"

  multi_site_active:
    rto: "Near-zero"
    rpo: "Near-zero"
    cost: "$$$$"
    description: "Active-active across regions. Traffic served from both regions simultaneously."
    aws_services:
      - "DynamoDB Global Tables or Aurora Global Database"
      - "Route53 latency/weighted routing"
      - "CloudFront with multi-origin"
      - "Global Accelerator"
      - "ECS/EKS in both regions"
    pros: "Minimal downtime and data loss"
    cons: "Highest cost, most complex to operate"
```

## AWS Cross-Region DR Implementation

```bash
# === Database Replication ===

# Create cross-region RDS read replica
aws rds create-db-instance-read-replica \
  --db-instance-identifier prod-db-dr-replica \
  --source-db-instance-identifier arn:aws:rds:us-east-1:123456789012:db:prod-db \
  --db-instance-class db.r6g.large \
  --region us-west-2 \
  --kms-key-id arn:aws:kms:us-west-2:123456789012:alias/rds-dr-key \
  --multi-az \
  --tags Key=Purpose,Value=DR Key=Environment,Value=production

# Create Aurora Global Database for near-zero RPO
aws rds create-global-cluster \
  --global-cluster-identifier prod-global-db \
  --source-db-cluster-identifier arn:aws:rds:us-east-1:123456789012:cluster:prod-aurora-cluster \
  --region us-east-1

# Add secondary region to Aurora Global Database
aws rds create-db-cluster \
  --db-cluster-identifier prod-aurora-dr \
  --global-cluster-identifier prod-global-db \
  --engine aurora-postgresql \
  --region us-west-2 \
  --kms-key-id arn:aws:kms:us-west-2:123456789012:alia
