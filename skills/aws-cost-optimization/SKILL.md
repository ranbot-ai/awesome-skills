---
name: aws-cost-optimization
description: Reduce AWS spend with rightsizing, autoscaling, commitment planning, and storage lifecycle policies. Use when running FinOps reviews, lowering cloud bills, or improving cost-per-request metrics. 
category: AI & Agents
source: antigravity
tags: [api, ai, agent, workflow, template, security, aws, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/aws-cost-optimization
---


# AWS Cost Optimization

Apply practical FinOps controls to reduce AWS spend without sacrificing reliability or performance.

## When to Use This Skill

- Monthly AWS bill spikes unexpectedly or exceeds budget thresholds
- Preparing cost reviews with engineering and finance teams
- Rightsizing EC2, RDS, EKS, or Lambda workloads after load testing
- Choosing between Savings Plans, Reserved Instances, or on-demand pricing
- Setting up automated budget alerts and anomaly detection
- Cleaning up unused resources (unattached EBS, idle load balancers, old snapshots)
- Optimizing data transfer costs across regions and AZs

## Prerequisites

- AWS CLI v2 installed and configured (`aws configure`)
- IAM permissions: `ce:*`, `budgets:*`, `ec2:Describe*`, `cloudwatch:PutMetricAlarm`, `s3:PutLifecycleConfiguration`
- Cost Explorer enabled in the AWS billing console (takes 24 hours to populate)
- Cost allocation tags activated in the Billing console

## Cost Review Workflow

1. Tag every resource by team, service, environment, and cost center.
2. Enable Cost Explorer and activate Cost and Usage Reports (CUR) to S3.
3. Identify top spend drivers by service, account, and tag.
4. Rightsize underutilized compute and storage based on CloudWatch metrics.
5. Apply commitment discounts (Savings Plans or RIs) for stable baseline usage.
6. Set budgets, anomaly alerts, and build KPI dashboards.
7. Review monthly and iterate.

## Cost Explorer CLI Commands

```bash
# Get cost and usage for the last 30 days grouped by service
aws ce get-cost-and-usage \
  --time-period Start=2026-02-01,End=2026-03-01 \
  --granularity MONTHLY \
  --metrics "BlendedCost" "UnblendedCost" "UsageQuantity" \
  --group-by Type=DIMENSION,Key=SERVICE

# Get cost forecast for the next 30 days
aws ce get-cost-forecast \
  --time-period Start=2026-03-24,End=2026-04-24 \
  --metric UNBLENDED_COST \
  --granularity MONTHLY

# Get cost grouped by a specific tag (e.g., team)
aws ce get-cost-and-usage \
  --time-period Start=2026-02-01,End=2026-03-01 \
  --granularity MONTHLY \
  --metrics "UnblendedCost" \
  --group-by Type=TAG,Key=team

# Get rightsizing recommendations for EC2
aws ce get-rightsizing-recommendation \
  --service "AmazonEC2" \
  --configuration '{"RecommendationTarget":"SAME_INSTANCE_FAMILY","BenefitsConsidered":true}'

# Get Savings Plans purchase recommendation
aws ce get-savings-plans-purchase-recommendation \
  --savings-plans-type COMPUTE_SP \
  --term-in-years ONE_YEAR \
  --payment-option NO_UPFRONT \
  --lookback-period-in-days SIXTY_DAYS

# Get Savings Plans utilization
aws ce get-savings-plans-utilization \
  --time-period Start=2026-02-01,End=2026-03-01 \
  --granularity MONTHLY

# Get Reserved Instance utilization
aws ce get-reservation-utilization \
  --time-period Start=2026-02-01,End=2026-03-01 \
  --granularity MONTHLY
```

## Budget Alerts

```bash
# Create a monthly cost budget with email alert at 80% and 100%
aws budgets create-budget \
  --account-id 123456789012 \
  --budget '{
    "BudgetName": "monthly-total",
    "BudgetLimit": {"Amount": "5000", "Unit": "USD"},
    "TimeUnit": "MONTHLY",
    "BudgetType": "COST",
    "CostFilters": {},
    "CostTypes": {
      "IncludeTax": true,
      "IncludeSubscription": true,
      "UseBlended": false
    }
  }' \
  --notifications-with-subscribers '[
    {
      "Notification": {
        "NotificationType": "ACTUAL",
        "ComparisonOperator": "GREATER_THAN",
        "Threshold": 80,
        "ThresholdType": "PERCENTAGE"
      },
      "Subscribers": [{"SubscriptionType": "EMAIL", "Address": "finops@example.com"}]
    },
    {
      "Notification": {
        "NotificationType": "ACTUAL",
        "ComparisonOperator": "GREATER_THAN",
        "Threshold": 100,
        "ThresholdType": "PERCENTAGE"
      },
      "Subscribers": [{"SubscriptionType": "EMAIL", "Address": "finops@example.com"}]
    }
  ]'

# List all budgets
aws budgets describe-budgets --account-id 123456789012

# Enable Cost Anomaly Detection monitor for all services
aws ce create-anomaly-monitor \
  --anomaly-monitor '{
    "MonitorName": "all-services",
    "MonitorType": "DIMENSIONAL",
    "MonitorDimension": "SERVICE"
  }'

# Create anomaly subscription (alert when impact > $50)
aws ce create-anomaly-subscription \
  --anomaly-subscription '{
    "SubscriptionName": "cost-alerts",
    "MonitorArnList": ["arn:aws:ce::123456789012:anomalymonitor/monitor-id"],
    "Subscribers": [{"Type": "EMAIL", "Address": "finops@example.com"}],
    "Threshold": 50,
    "Frequency": "DAILY"
  }'
```

## CloudWatch Cost Alarm

```bash
# Create alarm for estimated charges exceeding $4000
aws cloudwatch put-metric-alarm \
  --alarm-name "billing-alarm-4000" \
  --alarm-description "Alert when estimated charges exceed $4000" \
  --metric-name EstimatedCharges \
  --namespace AWS/Billing \
  --statistic Maximum \
  --period 21600 \
  --threshold 4000 \
  --comparison-operator GreaterThanThreshold \
  --evaluation-periods 1 \
  --dimen
