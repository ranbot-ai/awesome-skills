---
name: aws-lambda
description: Build and deploy serverless functions on AWS Lambda. Configure triggers, manage permissions, and optimize performance. Use when implementing serverless applications. 
category: AI & Agents
source: antigravity
tags: [python, node, api, ai, agent, automation, template, image, security, aws]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/aws-lambda
---


# AWS Lambda

Build serverless applications with AWS Lambda, covering function creation, event sources, layers, SAM templates, and cold start optimization.

## When to Use This Skill

- Building event-driven applications triggered by API Gateway, S3, SQS, or EventBridge
- Running scheduled tasks (cron) without managing servers
- Processing data streams from Kinesis or DynamoDB
- Building lightweight APIs with API Gateway or function URLs
- Implementing webhooks, Slack bots, or automation scripts
- Reducing compute costs for intermittent or bursty workloads

## Prerequisites

- AWS CLI v2 installed and configured
- IAM permissions: `lambda:*`, `iam:PassRole`, `logs:*`, `apigateway:*`, `s3:*`
- Python 3.11+, Node.js 20+, or another supported runtime installed locally
- (Optional) AWS SAM CLI for local development and deployment

## Create and Deploy a Function

```bash
# Create a deployment package
cd my-function
zip -r function.zip app.py

# Create the Lambda function
aws lambda create-function \
  --function-name my-api-handler \
  --runtime python3.12 \
  --handler app.handler \
  --role arn:aws:iam::123456789012:role/LambdaExecRole \
  --zip-file fileb://function.zip \
  --memory-size 256 \
  --timeout 30 \
  --environment 'Variables={STAGE=production,LOG_LEVEL=INFO}' \
  --architectures arm64 \
  --tracing-config Mode=Active \
  --tags '{"Team":"backend","Environment":"production"}'

# Update function code
aws lambda update-function-code \
  --function-name my-api-handler \
  --zip-file fileb://function.zip

# Update function configuration
aws lambda update-function-configuration \
  --function-name my-api-handler \
  --memory-size 512 \
  --timeout 60 \
  --environment 'Variables={STAGE=production,LOG_LEVEL=WARNING}'

# Publish a version (immutable snapshot)
aws lambda publish-version \
  --function-name my-api-handler \
  --description "v1.2.0 - added rate limiting"

# Create an alias pointing to the version
aws lambda create-alias \
  --function-name my-api-handler \
  --name live \
  --function-version 3

# Weighted alias for canary deployments (90% v3, 10% v4)
aws lambda update-alias \
  --function-name my-api-handler \
  --name live \
  --function-version 4 \
  --routing-config '{"AdditionalVersionWeights":{"3":0.9}}'
```

## Function Code Examples

```python
# app.py - API Gateway handler with structured logging
import json
import logging
import os

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

def handler(event, context):
    """Handle API Gateway proxy event."""
    logger.info("Request: %s %s", event["httpMethod"], event["path"])

    try:
        body = json.loads(event.get("body", "{}"))
        result = process_request(body)

        return {
            "statusCode": 200,
            "headers": {
                "Content-Type": "application/json",
                "X-Request-Id": context.aws_request_id
            },
            "body": json.dumps(result)
        }
    except ValueError as e:
        logger.warning("Validation error: %s", e)
        return {"statusCode": 400, "body": json.dumps({"error": str(e)})}
    except Exception as e:
        logger.exception("Unhandled error")
        return {"statusCode": 500, "body": json.dumps({"error": "Internal server error"})}

def process_request(body):
    return {"message": "OK", "data": body}
```

```python
# sqs_processor.py - SQS batch processor with partial failure reporting
import json
import logging

logger = logging.getLogger()
logger.setLevel("INFO")

def handler(event, context):
    """Process SQS messages with partial batch failure reporting."""
    failed_ids = []

    for record in event["Records"]:
        try:
            body = json.loads(record["body"])
            logger.info("Processing message: %s", record["messageId"])
            process_message(body)
        except Exception as e:
            logger.error("Failed message %s: %s", record["messageId"], e)
            failed_ids.append(record["messageId"])

    # Return failed items so only those get retried
    return {
        "batchItemFailures": [
            {"itemIdentifier": msg_id} for msg_id in failed_ids
        ]
    }

def process_message(body):
    pass  # your logic here
```

## Lambda Layers

```bash
# Build a layer for Python dependencies
mkdir -p layer/python
pip install requests boto3-stubs -t layer/python/
cd layer
zip -r ../my-layer.zip python/

# Publish the layer
aws lambda publish-layer-version \
  --layer-name common-deps \
  --description "Shared Python dependencies" \
  --zip-file fileb://my-layer.zip \
  --compatible-runtimes python3.11 python3.12 \
  --compatible-architectures arm64 x86_64

# Attach layer to a function
aws lambda update-function-configuration \
  --function-name my-api-handler \
  --layers "arn:aws:lambda:us-east-1:123456789012:layer:common-deps:1"

# List available layers
aws lambda list-layers --compatible-runtime python3.12
```

## Event Source Mappings

```bash
# SQS trigger with batch pr
