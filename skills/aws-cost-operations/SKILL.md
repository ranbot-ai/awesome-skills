---
name: aws-cost-operations
description: AWS cost optimization, monitoring, and operational excellence expert. Use when analyzing AWS bills, estimating costs, setting up CloudWatch alarms, querying logs, auditing CloudTrail activity, or asse
category: Document Processing
source: antigravity
tags: [node, api, mcp, ai, workflow, document, security, kubernetes, aws, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/aws-cost-operations
---


# AWS Cost & Operations

This skill provides comprehensive guidance for AWS cost optimization, monitoring, observability, and operational excellence with integrated MCP servers.

## AWS Documentation Requirement

Always verify AWS facts using MCP tools (`mcp__aws-mcp__*` or `mcp__*awsdocs*__*`) before answering. The `aws-mcp-setup` dependency is auto-loaded — if MCP tools are unavailable, guide the user through that skill's setup flow.

## Integrated MCP Servers

This plugin provides 3 MCP servers:

### Bundled Servers

#### 1. AWS Pricing MCP Server (`pricing`)
**Purpose**: Pre-deployment cost estimation and optimization
- Estimate costs before deploying resources
- Compare pricing across regions
- Calculate Total Cost of Ownership (TCO)
- Evaluate different service options for cost efficiency

#### 2. AWS Cost Explorer MCP Server (`costexp`)
**Purpose**: Detailed cost analysis and reporting
- Analyze historical spending patterns
- Identify cost anomalies and trends
- Forecast future costs
- Analyze cost by service, region, or tag

#### 3. Amazon CloudWatch MCP Server (`cw`)
**Purpose**: Metrics, alarms, and logs analysis
- Query CloudWatch metrics and logs
- Create and manage CloudWatch alarms
- Troubleshoot operational issues
- Monitor resource utilization

> **Note**: The following servers are available separately via the Full AWS MCP Server (see `aws-mcp-setup` skill) and are not bundled with this plugin:
> - AWS Billing and Cost Management MCP — Real-time billing details
> - CloudWatch Application Signals MCP — APM and SLOs
> - AWS Managed Prometheus MCP — PromQL queries for containers
> - AWS CloudTrail MCP — API activity audit
> - AWS Well-Architected Security Assessment MCP — Security posture assessment

## When to Use This Skill

Use this skill when:
- Optimizing AWS costs and reducing spending
- Estimating costs before deployment
- Monitoring application and infrastructure performance
- Setting up observability and alerting
- Analyzing spending patterns and trends
- Investigating operational issues
- Auditing AWS activity and changes
- Assessing security posture
- Implementing operational excellence

## Cost Optimization Best Practices

### Pre-Deployment Cost Estimation

**Always estimate costs before deploying**:
1. Use **AWS Pricing MCP** to estimate resource costs
2. Compare pricing across different regions
3. Evaluate alternative service options
4. Calculate expected monthly costs
5. Plan for scaling and growth

**Example workflow**:
```
"Estimate the monthly cost of running a Lambda function with
1 million invocations, 512MB memory, 3-second duration in us-east-1"
```

### Cost Analysis and Optimization

**Regular cost reviews**:
1. Use **Cost Explorer MCP** to analyze spending trends
2. Identify cost anomalies and unexpected charges
3. Review costs by service, region, and environment
4. Compare actual vs. budgeted costs
5. Generate cost optimization recommendations

**Cost optimization strategies**:
- Right-size over-provisioned resources
- Use appropriate storage classes (S3, EBS)
- Implement auto-scaling for dynamic workloads
- Leverage Savings Plans and Reserved Instances
- Delete unused resources and snapshots
- Use cost allocation tags effectively

### Budget Monitoring

**Track spending against budgets**:
1. Use **Billing and Cost Management MCP** to monitor budgets
2. Set up budget alerts for threshold breaches
3. Review budget utilization regularly
4. Adjust budgets based on trends
5. Implement cost controls and governance

## Monitoring and Observability Best Practices

### CloudWatch Metrics and Alarms

**Implement comprehensive monitoring**:
1. Use **CloudWatch MCP** to query metrics and logs
2. Set up alarms for critical metrics:
   - CPU and memory utilization
   - Error rates and latency
   - Queue depths and processing times
   - API gateway throttling
   - Lambda errors and timeouts
3. Create CloudWatch dashboards for visualization
4. Use log insights for troubleshooting

**Example alarm scenarios**:
- Lambda error rate > 1%
- EC2 CPU utilization > 80%
- API Gateway 4xx/5xx error spike
- DynamoDB throttled requests
- ECS task failures

### Application Performance Monitoring

**Monitor application health**:
1. Use **CloudWatch Application Signals MCP** for APM
2. Track service-level objectives (SLOs)
3. Monitor application dependencies
4. Identify performance bottlenecks
5. Set up distributed tracing

### Container and Kubernetes Monitoring

**For containerized workloads**:
1. Use **AWS Managed Prometheus MCP** for metrics
2. Monitor container resource utilization
3. Track pod and node health
4. Create PromQL queries for custom metrics
5. Set up alerts for container anomalies

## Audit and Security Best Practices

### CloudTrail Activity Analysis

**Audit AWS activity**:
1. Use **CloudTrail MCP** to analyze API activity
2. Track who made changes to resources
3. Investigate security incidents
4. Monitor for suspicious activity patterns
5. Audit compliance with policies

**Co
