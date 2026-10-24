---
name: cdn-setup
description: Configure CDNs for content delivery. Set up CloudFront, Cloudflare, and Fastly. Use when optimizing global content delivery. 
category: AI & Agents
source: antigravity
tags: [javascript, api, ai, agent, template, image, security, aws, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/cdn-setup
---


# CDN Setup

Configure content delivery networks for fast, reliable global asset delivery with proper caching, invalidation, and security.

## When to Use

- Serving static assets (JS, CSS, images, fonts) globally with low latency.
- Offloading traffic from origin servers to reduce compute costs.
- Adding TLS termination and DDoS protection at the edge.
- Implementing geo-based routing or content restrictions.
- Accelerating API responses with edge caching.

Examples use placeholders and create billable resources. Confirm the zone/distribution/account and rollback before provisioning, changing DNS/cache rules or purging. Cache only intentionally public responses; bypass authenticated, tenant-specific and sensitive routes even when paths resemble static assets. Do not strip query parameters that carry authorization or content identity.

## Prerequisites

- Domain with DNS management access.
- Origin server or S3/R2 bucket with content to serve.
- AWS CLI configured (for CloudFront).
- Cloudflare account with zone configured (for Cloudflare CDN).
- Terraform 1.5+ (for infrastructure-as-code examples).

## AWS CloudFront

### Create a Distribution via CLI

```bash
# Create an S3 origin distribution with OAC (Origin Access Control)
aws cloudfront create-distribution --distribution-config '{
  "CallerReference": "my-site-'$(date +%s)'",
  "Comment": "Production site CDN",
  "Enabled": true,
  "Origins": {
    "Quantity": 1,
    "Items": [{
      "Id": "s3-origin",
      "DomainName": "my-bucket.s3.us-east-1.amazonaws.com",
      "OriginPath": "",
      "S3OriginConfig": {
        "OriginAccessIdentity": ""
      },
      "OriginAccessControlId": "E2QWRUHAPOMQZL"
    }]
  },
  "DefaultCacheBehavior": {
    "TargetOriginId": "s3-origin",
    "ViewerProtocolPolicy": "redirect-to-https",
    "AllowedMethods": {
      "Quantity": 2,
      "Items": ["GET", "HEAD"]
    },
    "CachePolicyId": "658327ea-f89d-4fab-a63d-7e88639e58f6",
    "Compress": true
  },
  "DefaultRootObject": "index.html",
  "PriceClass": "PriceClass_100",
  "ViewerCertificate": {
    "ACMCertificateArn": "arn:aws:acm:us-east-1:123456789:certificate/abc-123",
    "SSLSupportMethod": "sni-only",
    "MinimumProtocolVersion": "TLSv1.2_2021"
  },
  "Aliases": {
    "Quantity": 1,
    "Items": ["www.example.com"]
  },
  "CustomErrorResponses": {
    "Quantity": 1,
    "Items": [{
      "ErrorCode": 404,
      "ResponseCode": "200",
      "ResponsePagePath": "/index.html",
      "ErrorCachingMinTTL": 10
    }]
  }
}'
```

### Cache Invalidation

```bash
# Invalidate specific paths
aws cloudfront create-invalidation \
  --distribution-id E1A2B3C4D5E6F7 \
  --paths "/index.html" "/css/*" "/js/*"

# Invalidate everything (costs apply per path)
aws cloudfront create-invalidation \
  --distribution-id E1A2B3C4D5E6F7 \
  --paths "/*"

# Check invalidation status
aws cloudfront get-invalidation \
  --distribution-id E1A2B3C4D5E6F7 \
  --id I1A2B3C4D5E6F7

# List recent invalidations
aws cloudfront list-invalidations --distribution-id E1A2B3C4D5E6F7
```

### CloudFront Functions (Lightweight Edge Logic)

```javascript
// URL rewrite function — add index.html to directory requests
function handler(event) {
  var request = event.request;
  var uri = request.uri;

  if (uri.endsWith('/')) {
    request.uri += 'index.html';
  } else if (!uri.includes('.')) {
    request.uri += '/index.html';
  }

  return request;
}
```

### CloudFront with Terraform

This is a partial configuration: supply the referenced bucket, certificate and API origin, and a least-privilege S3 bucket policy granting this distribution access through OAC. OAC creation alone does not grant bucket reads. Review SPA fallbacks: private S3 origins may return 403 for missing objects; never turn genuine authorization failures into successful HTML responses.

```hcl
# cloudfront.tf
resource "aws_cloudfront_distribution" "site" {
  enabled             = true
  is_ipv6_enabled     = true
  default_root_object = "index.html"
  aliases             = ["www.example.com"]
  price_class         = "PriceClass_100"

  origin {
    domain_name              = aws_s3_bucket.site.bucket_regional_domain_name
    origin_id                = "s3-origin"
    origin_access_control_id = aws_cloudfront_origin_access_control.oac.id
  }

  default_cache_behavior {
    allowed_methods  = ["GET", "HEAD"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "s3-origin"

    cache_policy_id          = "658327ea-f89d-4fab-a63d-7e88639e58f6" # CachingOptimized
    origin_request_policy_id = "88a5eaf4-2fd4-4709-b370-b4c650ea3fcf" # CORS-S3Origin

    viewer_protocol_policy = "redirect-to-https"
    compress               = true
  }

  # SPA fallback
  custom_error_response {
    error_code         = 404
    response_code      = 200
    response_page_path = "/index.html"
  }

  # API pass-through (no caching): add a real origin block with
  # origin_id = "api-origin" and verified custom_origin_config first.
  ordered_cache_b
