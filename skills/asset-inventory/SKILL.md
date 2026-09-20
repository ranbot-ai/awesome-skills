---
name: asset-inventory
description: Maintain IT asset inventory and configuration management database. Track hardware, software, and cloud resources. Use when managing IT assets. 
category: AI & Agents
source: antigravity
tags: [markdown, api, ai, agent, workflow, template, image, security, aws, gcp]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/asset-inventory
---


# Asset Inventory

Maintain comprehensive IT asset inventory using automated discovery, AWS Config rules, cloud asset discovery scripts, CMDB integration, and tagging enforcement for compliance and operational visibility.

## Asset Categories and Schema

```yaml
asset_categories:
  compute:
    cloud:
      - EC2 instances / Azure VMs / GCE instances
      - Lambda functions / Azure Functions / Cloud Functions
      - ECS/EKS clusters and tasks
      - Container images in registries
    on_premise:
      - Physical servers
      - Virtual machines (VMware, Hyper-V)

  storage:
    - S3 buckets / Azure Storage / GCS buckets
    - EBS volumes / Managed Disks / Persistent Disks
    - RDS instances / Azure SQL / Cloud SQL
    - DynamoDB tables / Cosmos DB / Firestore
    - EFS / Azure Files / Filestore

  network:
    - VPCs / VNets / VPC Networks
    - Load balancers (ALB, NLB, Azure LB, GCP LB)
    - DNS zones and records
    - VPN gateways and connections
    - CDN distributions

  security:
    - IAM users, roles, and policies
    - KMS keys / Key Vault keys
    - Certificates (ACM, Key Vault, Certificate Manager)
    - Security groups / NSGs / Firewall rules
    - WAF configurations

  applications:
    - SaaS subscriptions
    - Licensed software
    - Custom applications
    - APIs and integrations

  endpoints:
    - Laptops and desktops
    - Mobile devices
    - Printers and peripherals

asset_record_schema:
  required_fields:
    asset_id: "Unique identifier (auto-generated)"
    name: "Human-readable name"
    type: "Category from above taxonomy"
    provider: "AWS / Azure / GCP / On-Premise / SaaS"
    account_or_subscription: "Cloud account ID"
    region: "Deployment region/location"
    owner: "Team or individual responsible"
    data_classification: "Public / Internal / Confidential / Restricted"
    environment: "Production / Staging / Development / Sandbox"
    status: "Active / Decommissioning / Retired"
    created_date: "When the asset was provisioned"
    last_seen: "Last automated discovery timestamp"

  optional_fields:
    cost_center: "For cost allocation"
    compliance_scope: "SOC2 / HIPAA / PCI / None"
    backup_policy: "Backup schedule reference"
    dr_tier: "Critical / Essential / Standard / Non-essential"
    expiration_date: "For time-limited resources"
    tags: "Key-value pairs from cloud provider"
    dependencies: "Upstream and downstream services"
```

## AWS Resource Discovery Script

```bash
#!/usr/bin/env bash
# aws-asset-discovery.sh - Discover and inventory all AWS resources

OUTPUT_DIR="./asset-inventory/aws/$(date +%Y-%m-%d)"
mkdir -p "$OUTPUT_DIR"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

echo "=== AWS Asset Discovery for Account $ACCOUNT_ID ==="

# EC2 Instances
echo "--- EC2 Instances ---"
aws ec2 describe-instances \
  --query 'Reservations[*].Instances[*].{
    InstanceId:InstanceId,
    Type:InstanceType,
    State:State.Name,
    AZ:Placement.AvailabilityZone,
    VpcId:VpcId,
    PrivateIP:PrivateIpAddress,
    PublicIP:PublicIpAddress,
    LaunchTime:LaunchTime,
    Name:Tags[?Key==`Name`].Value|[0],
    Owner:Tags[?Key==`Owner`].Value|[0],
    Environment:Tags[?Key==`Environment`].Value|[0]
  }' --output json | jq 'flatten' > "$OUTPUT_DIR/ec2-instances.json"

# RDS Databases
echo "--- RDS Instances ---"
aws rds describe-db-instances \
  --query 'DBInstances[*].{
    DBInstanceId:DBInstanceIdentifier,
    Engine:Engine,
    EngineVersion:EngineVersion,
    Class:DBInstanceClass,
    Status:DBInstanceStatus,
    MultiAZ:MultiAZ,
    Encrypted:StorageEncrypted,
    Endpoint:Endpoint.Address,
    BackupRetention:BackupRetentionPeriod
  }' --output json > "$OUTPUT_DIR/rds-instances.json"

# S3 Buckets
echo "--- S3 Buckets ---"
aws s3api list-buckets --query 'Buckets[*].{Name:Name,Created:CreationDate}' --output json | \
  jq -c '.[]' | while read -r bucket; do
    name=$(echo "$bucket" | jq -r '.Name')
    region=$(aws s3api get-bucket-location --bucket "$name" --query 'LocationConstraint' --output text 2>/dev/null)
    encryption=$(aws s3api get-bucket-encryption --bucket "$name" 2>/dev/null | jq -r '.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm' 2>/dev/null)
    versioning=$(aws s3api get-bucket-versioning --bucket "$name" --query 'Status' --output text 2>/dev/null)
    echo "{\"Name\":\"$name\",\"Region\":\"${region:-us-east-1}\",\"Encryption\":\"${encryption:-none}\",\"Versioning\":\"${versioning:-Disabled}\"}"
  done | jq -s '.' > "$OUTPUT_DIR/s3-buckets.json"

# Lambda Functions
echo "--- Lambda Functions ---"
aws lambda list-functions \
  --query 'Functions[*].{
    Name:FunctionName,
    Runtime:Runtime,
    MemorySize:MemorySize,
    Timeout:Timeout,
    LastModified:LastModified,
    CodeSize:CodeSize
  }' --output json > "$OUTPUT_DIR/lambda-functions.json"

# VPCs and Security Groups
echo "--- VPCs ---"
aws ec2 describe-vpcs \
  --query 'Vpcs[*].{
    VpcId:VpcId,
    Cid
