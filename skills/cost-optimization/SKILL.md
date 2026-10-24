---
name: cost-optimization
description: Strategies and patterns for optimizing cloud costs across AWS, Azure, and GCP. 
category: Document Processing
source: antigravity
tags: [xlsx, ai, template, spreadsheet, aws, gcp, azure, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/cost-optimization
---

## Bundled upstream support

Supporting files are included at skill-relative paths. See [UPSTREAM-NOTICE.md](UPSTREAM-NOTICE.md) for their pinned sources, licenses, hashes, and import changes.

## Supporting material availability

These paths remain unavailable in this catalog copy:

- `<support-root>/assets/cost-analysis-template.xlsx`

Do not invoke a step that requires one of these files. Obtain the original material and review its dependencies, license, and effects before use. Independent inline steps and the bundled helpers can proceed within the user’s authorized scope.

# Cloud Cost Optimization

Strategies and patterns for optimizing cloud costs across AWS, Azure, and GCP.

## Do not use this skill when

- The task is unrelated to cloud cost optimization
- You need a different domain or tool outside this scope

## Instructions

- Clarify goals, constraints, and required inputs.
- Apply relevant best practices and validate outcomes.
- Provide actionable steps and verification.

## Purpose

Implement systematic cost optimization strategies to reduce cloud spending while maintaining performance and reliability.

## Use this skill when

- Reduce cloud spending
- Right-size resources
- Implement cost governance
- Optimize multi-cloud costs
- Meet budget constraints

## Evidence and irreversible commitments

All discount percentages/terms and example instance sizes below are historical illustrations, not current quotes or workload recommendations. Verify provider/region/service eligibility and actual effective utilization before buying commitments; reservations/discount plans are financial commitments with changing exchange/cancellation rules. Use read-only billing/utilization first, compare equal workload/reliability windows and include egress, storage minimums, retrieval, taxes and idle costs. Deletion/lifecycle expiry, downsizing and alert subscriptions require exact-target authorization and tested recovery. Budget alerts are notifications, not a spending cap; serverless can retain baseline/storage/provisioned costs.

## Cost Optimization Framework

### 1. Visibility
- Implement cost allocation tags
- Use cloud cost management tools
- Set up budget alerts
- Create cost dashboards

### 2. Right-Sizing
- Analyze resource utilization
- Downsize over-provisioned resources
- Use auto-scaling
- Remove idle resources

### 3. Pricing Models
- Use reserved capacity
- Leverage spot/preemptible instances
- Implement savings plans
- Use committed use discounts

### 4. Architecture Optimization
- Use managed services
- Implement caching
- Optimize data transfer
- Use lifecycle policies

## AWS Cost Optimization

### Reserved Instances
```
Savings: 30-72% vs On-Demand
Term: 1 or 3 years
Payment: All/Partial/No upfront
Flexibility: Standard or Convertible
```

### Savings Plans
```
Compute Savings Plans: 66% savings
EC2 Instance Savings Plans: 72% savings
Applies to: EC2, Fargate, Lambda
Flexible across: Instance families, regions, OS
```

### Spot Instances
```
Savings: Up to 90% vs On-Demand
Best for: Batch jobs, CI/CD, stateless workloads
Risk: 2-minute interruption notice
Strategy: Mix with On-Demand for resilience
```

### S3 Cost Optimization
```hcl
resource "aws_s3_bucket_lifecycle_configuration" "example" {
  bucket = aws_s3_bucket.example.id

  rule {
    id     = "transition-to-ia"
    status = "Enabled"

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    expiration {
      days = 365
    }
  }
}
```

## Azure Cost Optimization

### Reserved VM Instances
- 1 or 3 year terms
- Up to 72% savings
- Flexible sizing
- Exchangeable

### Azure Hybrid Benefit
- Use existing Windows Server licenses
- Up to 80% savings with RI
- Available for Windows and SQL Server

### Azure Advisor Recommendations
- Right-size VMs
- Delete unused resources
- Use reserved capacity
- Optimize storage

## GCP Cost Optimization

### Committed Use Discounts
- 1 or 3 year commitment
- Up to 57% savings
- Applies to vCPUs and memory
- Resource-based or spend-based

### Sustained Use Discounts
- Automatic discounts
- Up to 30% for running instances
- No commitment required
- Applies to Compute Engine, GKE

### Preemptible VMs
- Up to 80% savings
- 24-hour maximum runtime
- Best for batch workloads

## Tagging Strategy

### AWS Tagging
```hcl
locals {
  common_tags = {
    Environment = "production"
    Project     = "my-project"
    CostCenter  = "engineering"
    Owner       = "team@example.com"
    ManagedBy   = "terraform"
  }
}

resource "aws_instance" "example" {
  ami           = "ami-12345678"
  instance_type = "t3.medium"

  tags = merge(
    local.common_tags,
    {
      Name = "web-server"
    }
  )
}
```

**Reference:** See `references/tagging-standards.md`

## Cost Monitoring

### Budget Alerts
```hcl
# AWS Budget
resource "aws_budgets_budget" "monthly" {
  name              = "monthly-budget"
  budget_type   
