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
    measurement: "From the agreed service disruption point to verified recovery; record detection/declaration separately"
    factors:
      - Failover automation maturity
      - Data replication lag
      - DNS propagation time
      - Application warm-up time
      - Verification procedures

  RPO:
    definition: "Recovery Point Objective - maximum acceptable data loss"
    measurement: "Gap between latest recoverable consistent data and disruption; backups/replication may be stale or corrupted"
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
      - "DynamoDB Global Tables where appropriate; Aurora Global Database normally has one writer region, not multi-region active-active writes"
      - "Route53 latency/weighted routing"
      - "CloudFront with multi-origin"
      - "Global Accelerator"
      - "ECS/EKS in both regions"
    pros: "Minimal downtime and data loss"
    cons: "Highest cost, most complex to operate"
```

## AWS Cross-Region DR Implementation

Fragments below provision or replace paid production configuration: confirm exact
account, engine/version support, target region, KMS/IAM grants, backups and approved
change window first. The listed tier timings/frequencies are planning examples,
not platform guarantees or universal compliance rules. Aurora secondary-cluster
creation also needs supported regional engine/version, subnet/security settings
and instances; a cluster object alone is not a working DR application.
S3 requires versioning on both buckets, replication-role/KMS permissions and
explicit handling of existing objects; put-bucket-replication replaces existing
rules, so merge a reviewed snapshot rather than overwriting it. Replication is not
an immutable backup and can replicate corruption/deletion. Use a pr
