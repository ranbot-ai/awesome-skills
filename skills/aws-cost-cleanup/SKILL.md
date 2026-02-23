---
name: aws-cost-cleanup
description: Automated cleanup of unused AWS resources to reduce costs 
category: Document Processing
source: antigravity
tags: [python, api, ai, automation, workflow, document, aws, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/aws-cost-cleanup
---


# AWS Cost Cleanup

Automate the identification and removal of unused AWS resources to eliminate waste.

## When to Use This Skill

Use this skill when you need to automatically clean up unused AWS resources to reduce costs and eliminate waste.

## Automated Cleanup Targets

**Storage**
- Unattached EBS volumes
- Old EBS snapshots (>90 days)
- Incomplete multipart S3 uploads
- Old S3 versions in versioned buckets

**Compute**
- Stopped EC2 instances (>30 days)
- Unused AMIs and associated snapshots
- Unused Elastic IPs

**Networking**
- Unused Elastic Load Balancers
- Unused NAT Gateways
- Orphaned ENIs

## Cleanup Scripts

### Safe Cleanup (Dry-Run First)

```bash
#!/bin/bash
# cleanup-unused-ebs.sh

echo "Finding unattached EBS volumes..."
VOLUMES=$(aws ec2 describe-volumes \
  --filters Name=status,Values=available \
  --query 'Volumes[*].VolumeId' \
  --output text)

for vol in $VOLUMES; do
  echo "Would delete: $vol"
  # Uncomment to actually delete:
  # aws ec2 delete-volume --volume-id $vol
done
```

```bash
#!/bin/bash
# cleanup-old-snapshots.sh

CUTOFF_DATE=$(date -d '90 days ago' --iso-8601)

aws ec2 describe-snapshots --owner-ids self \
  --query "Snapshots[?StartTime<='$CUTOFF_DATE'].[SnapshotId,StartTime,VolumeSize]" \
  --output text | while read snap_id start_time size; do
  
  echo "Snapshot: $snap_id (Created: $start_time, Size: ${size}GB)"
  # Uncomment to delete:
  # aws ec2 delete-snapshot --snapshot-id $snap_id
done
```

```bash
#!/bin/bash
# release-unused-eips.sh

aws ec2 describe-addresses \
  --query 'Addresses[?AssociationId==null].[AllocationId,PublicIp]' \
  --output text | while read alloc_id public_ip; do
  
  echo "Would release: $public_ip ($alloc_id)"
  # Uncomment to release:
  # aws ec2 release-address --allocation-id $alloc_id
done
```

### S3 Lifecycle Automation

```bash
# Apply lifecycle policy to transition old objects to cheaper storage
cat > lifecycle-policy.json <<EOF
{
  "Rules": [
    {
      "Id": "Archive old objects",
      "Status": "Enabled",
      "Transitions": [
        {
          "Days": 90,
          "StorageClass": "STANDARD_IA"
        },
        {
          "Days": 180,
          "StorageClass": "GLACIER"
        }
      ],
      "NoncurrentVersionExpiration": {
        "NoncurrentDays": 30
      },
      "AbortIncompleteMultipartUpload": {
        "DaysAfterInitiation": 7
      }
    }
  ]
}
EOF

aws s3api put-bucket-lifecycle-configuration \
  --bucket my-bucket \
  --lifecycle-configuration file://lifecycle-policy.json
```

## Cost Impact Calculator

```python
#!/usr/bin/env python3
# calculate-savings.py

import boto3
from datetime import datetime, timedelta

ec2 = boto3.client('ec2')

# Calculate EBS volume savings
volumes = ec2.describe_volumes(
    Filters=[{'Name': 'status', 'Values': ['available']}]
)

total_size = sum(v['Size'] for v in volumes['Volumes'])
monthly_cost = total_size * 0.10  # $0.10/GB-month for gp3

print(f"Unattached EBS Volumes: {len(volumes['Volumes'])}")
print(f"Total Size: {total_size} GB")
print(f"Monthly Savings: ${monthly_cost:.2f}")

# Calculate Elastic IP savings
addresses = ec2.describe_addresses()
unused = [a for a in addresses['Addresses'] if 'AssociationId' not in a]

eip_cost = len(unused) * 3.65  # $0.005/hour * 730 hours
print(f"\nUnused Elastic IPs: {len(unused)}")
print(f"Monthly Savings: ${eip_cost:.2f}")

print(f"\nTotal Monthly Savings: ${monthly_cost + eip_cost:.2f}")
print(f"Annual Savings: ${(monthly_cost + eip_cost) * 12:.2f}")
```

## Automated Cleanup Lambda

```python
import boto3
from datetime import datetime, timedelta

def lambda_handler(event, context):
    ec2 = boto3.client('ec2')
    
    # Delete unattached volumes older than 7 days
    volumes = ec2.describe_volumes(
        Filters=[{'Name': 'status', 'Values': ['available']}]
    )
    
    cutoff = datetime.now() - timedelta(days=7)
    deleted = 0
    
    for vol in volumes['Volumes']:
        create_time = vol['CreateTime'].replace(tzinfo=None)
        if create_time < cutoff:
            try:
                ec2.delete_volume(VolumeId=vol['VolumeId'])
                deleted += 1
                print(f"Deleted volume: {vol['VolumeId']}")
            except Exception as e:
                print(f"Error deleting {vol['VolumeId']}: {e}")
    
    return {
        'statusCode': 200,
        'body': f'Deleted {deleted} volumes'
    }
```

## Cleanup Workflow

1. **Discovery Phase** (Read-only)
   - Run all describe commands
   - Generate cost impact report
   - Review with team

2. **Validation Phase**
   - Verify resources are truly unused
   - Check for dependencies
   - Notify resource owners

3. **Execution Phase** (Dry-run first)
   - Run cleanup scripts with dry-run
   - Review proposed changes
   - Execute actual cleanup

4. **Verification Phase**
   - Confirm deletions
   - Monitor for issues
   - Document savings

## Safety Checklist

- [ ] Run in dry-run mode first
- [ ] Verify resources have no dependencies
- [ ] Check re
