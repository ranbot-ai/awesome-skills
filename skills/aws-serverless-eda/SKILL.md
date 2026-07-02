---
name: aws-serverless-eda
description: AWS serverless and event-driven architecture expert based on Well-Architected Framework. Use when building serverless APIs, Lambda functions, REST APIs, microservices, or async workflows. Covers Lambd
category: Document Processing
source: antigravity
tags: [python, typescript, node, api, mcp, ai, workflow, design, document, presentation]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/aws-serverless-eda
---


# AWS Serverless & Event-Driven Architecture

This skill provides comprehensive guidance for building serverless applications and event-driven architectures on AWS based on Well-Architected Framework principles.

## AWS Documentation Requirement

Always verify AWS facts using MCP tools (`mcp__aws-mcp__*` or `mcp__*awsdocs*__*`) before answering. The `aws-mcp-setup` dependency is auto-loaded — if MCP tools are unavailable, guide the user through that skill's setup flow.

## Serverless MCP Servers

This skill leverages the CDK MCP server (provided via `aws-cdk-development` dependency) and AWS Documentation MCP for serverless guidance.

> **Note**: The following AWS MCP servers are available separately via the Full AWS MCP Server (see `aws-mcp-setup` skill) and are not bundled with this plugin:
> - AWS Serverless MCP — SAM CLI lifecycle (init, deploy, local test)
> - AWS Lambda Tool MCP — Direct Lambda invocation
> - AWS Step Functions MCP — Workflow orchestration
> - Amazon SNS/SQS MCP — Messaging and queue management

## When to Use This Skill

Use this skill when:
- Building serverless applications with Lambda
- Designing event-driven architectures
- Implementing microservices patterns
- Creating asynchronous processing workflows
- Orchestrating multi-service transactions
- Building real-time data processing pipelines
- Implementing saga patterns for distributed transactions
- Designing for scale and resilience

## AWS Well-Architected Serverless Design Principles

### 1. Speedy, Simple, Singular

**Functions should be concise and single-purpose**

```typescript
// ✅ GOOD - Single purpose, focused function
export const processOrder = async (event: OrderEvent) => {
  // Only handles order processing
  const order = await validateOrder(event);
  await saveOrder(order);
  await publishOrderCreatedEvent(order);
  return { statusCode: 200, body: JSON.stringify({ orderId: order.id }) };
};

// ❌ BAD - Function does too much
export const handleEverything = async (event: any) => {
  // Handles orders, inventory, payments, shipping...
  // Too many responsibilities
};
```

**Keep functions environmentally efficient and cost-aware**:
- Minimize cold start times
- Optimize memory allocation
- Use provisioned concurrency only when needed
- Leverage connection reuse

### 2. Think Concurrent Requests, Not Total Requests

**Design for concurrency, not volume**

Lambda scales horizontally - design considerations should focus on:
- Concurrent execution limits
- Downstream service throttling
- Shared resource contention
- Connection pool sizing

```typescript
// Consider concurrent Lambda executions accessing DynamoDB
const table = new dynamodb.Table(this, 'Table', {
  billingMode: dynamodb.BillingMode.PAY_PER_REQUEST, // Auto-scales with load
});

// Or with provisioned capacity + auto-scaling
const table = new dynamodb.Table(this, 'Table', {
  billingMode: dynamodb.BillingMode.PROVISIONED,
  readCapacity: 5,
  writeCapacity: 5,
});

// Enable auto-scaling for concurrent load
table.autoScaleReadCapacity({ minCapacity: 5, maxCapacity: 100 });
table.autoScaleWriteCapacity({ minCapacity: 5, maxCapacity: 100 });
```

### 3. Share Nothing

**Function runtime environments are short-lived**

```typescript
// ❌ BAD - Relying on local file system
export const handler = async (event: any) => {
  fs.writeFileSync('/tmp/data.json', JSON.stringify(data)); // Lost after execution
};

// ✅ GOOD - Use persistent storage
export const handler = async (event: any) => {
  await s3.putObject({
    Bucket: process.env.BUCKET_NAME,
    Key: 'data.json',
    Body: JSON.stringify(data),
  });
};
```

**State management**:
- Use DynamoDB for persistent state
- Use Step Functions for workflow state
- Use ElastiCache for session state
- Use S3 for file storage

### 4. Assume No Hardware Affinity

**Applications must be hardware-agnostic**

Infrastructure can change without notice:
- Lambda functions can run on different hardware
- Container instances can be replaced
- No assumption about underlying infrastructure

**Design for portability**:
- Use environment variables for configuration
- Avoid hardware-specific optimizations
- Test across different environments

### 5. Orchestrate with State Machines, Not Function Chaining

**Use Step Functions for orchestration**

```typescript
// ❌ BAD - Lambda function chaining
export const handler1 = async (event: any) => {
  const result = await processStep1(event);
  await lambda.invoke({
    FunctionName: 'handler2',
    Payload: JSON.stringify(result),
  });
};

// ✅ GOOD - Step Functions orchestration
const stateMachine = new stepfunctions.StateMachine(this, 'OrderWorkflow', {
  definition: stepfunctions.Chain
    .start(validateOrder)
    .next(processPayment)
    .next(shipOrder)
    .next(sendConfirmation),
});
```

**Benefits of Step Functions**:
- Visual workflow representation
- Built-in error handling and retries
- Execution history and debugging
- Parallel and sequential execution
- Service integrat
