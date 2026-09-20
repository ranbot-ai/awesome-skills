---
name: access-review
description: Conduct periodic access reviews and certifications. Implement access governance and recertification workflows. Use when managing access compliance. 
category: Document Processing
source: antigravity
tags: [python, markdown, api, ai, agent, automation, workflow, template, document, security]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/access-review
---


# Access Review

Implement periodic access review processes for AWS IAM, GitHub, Okta, and other identity providers, including automated reporting, certification workflows, and unused permission detection.

## Access Review Process

```yaml
access_review_workflow:
  1_scope:
    actions:
      - Define systems in scope for the review cycle
      - Identify review owners (managers, system owners)
      - Set review timeline and deadlines
      - Generate access inventory from all identity sources
    frequency:
      privileged_access: Quarterly
      standard_access: Semi-annually
      service_accounts: Quarterly
      api_keys: Monthly

  2_extract:
    actions:
      - Pull current access data from all systems
      - Correlate identities across platforms (SSO mapping)
      - Enrich with last login and activity data
      - Flag accounts for review (inactive, over-privileged, orphaned)

  3_review:
    actions:
      - Assign review items to appropriate managers
      - Manager certifies each user's access (approve/revoke/modify)
      - Risk-based prioritization (privileged users reviewed first)
      - Escalate non-responses after deadline
    decisions:
      approve: "Access is appropriate for current role"
      modify: "Access needs adjustment (reduce/change scope)"
      revoke: "Access is no longer needed"

  4_remediate:
    actions:
      - Revoke access flagged for removal
      - Modify access as directed by reviewers
      - Document exceptions with justification
      - Confirm changes with system owners
    sla:
      revocations: "Complete within 5 business days of decision"
      modifications: "Complete within 10 business days"
      exceptions: "Approved by security team, documented, time-limited"

  5_report:
    actions:
      - Generate completion metrics (% reviewed, % on time)
      - Document all decisions and actions taken
      - Archive evidence for compliance audits
      - Identify process improvements for next cycle
```

## AWS IAM Access Review Scripts

```bash
#!/usr/bin/env bash
# aws-iam-review.sh - Comprehensive IAM access review report

OUTPUT_DIR="./access-review/$(date +%Y-%m)"
mkdir -p "$OUTPUT_DIR"

echo "=== AWS IAM Access Review ==="

# Generate credential report
aws iam generate-credential-report > /dev/null
sleep 10
aws iam get-credential-report --output text --query Content | \
  base64 -d > "$OUTPUT_DIR/credential-report.csv"

echo "--- Users Without MFA ---"
aws iam get-credential-report --output text --query Content | base64 -d | \ <!-- security-allowlist: documented payload decoding technique reference, do not execute outside authorized scope -->
  awk -F, 'NR>1 && $4=="true" && $8=="false" {print $1}' | \
  tee "$OUTPUT_DIR/users-without-mfa.txt"

echo "--- Inactive Users (90+ days) ---"
THRESHOLD=$(date -d '90 days ago' +%Y-%m-%dT%H:%M:%S 2>/dev/null || date -v-90d +%Y-%m-%dT%H:%M:%S)
aws iam get-credential-report --output text --query Content | base64 -d | \ <!-- security-allowlist: documented payload decoding technique reference, do not execute outside authorized scope -->
  awk -F, -v t="$THRESHOLD" 'NR>1 && $5!="N/A" && $5!="no_information" && $5<t {
    print $1","$5
  }' | tee "$OUTPUT_DIR/inactive-users.csv"

echo "--- Stale Access Keys (90+ days unused) ---"
for user in $(aws iam list-users --query 'Users[*].UserName' --output text); do
  for key_id in $(aws iam list-access-keys --user-name "$user" \
    --query 'AccessKeyMetadata[?Status==`Active`].AccessKeyId' --output text); do
    last_used=$(aws iam get-access-key-last-used --access-key-id "$key_id" \
      --query 'AccessKeyLastUsed.LastUsedDate' --output text)
    if [ "$last_used" = "None" ] || [ "$last_used" \< "$THRESHOLD" ]; then
      echo "$user,$key_id,$last_used"
    fi
  done
done | tee "$OUTPUT_DIR/stale-access-keys.csv"

echo "--- Users With Admin Policies ---"
for user in $(aws iam list-users --query 'Users[*].UserName' --output text); do
  policies=$(aws iam list-attached-user-policies --user-name "$user" \
    --query 'AttachedPolicies[*].PolicyName' --output text)
  if echo "$policies" | grep -qi "admin\|fullaccess"; then
    groups=$(aws iam list-groups-for-user --user-name "$user" \
      --query 'Groups[*].GroupName' --output text)
    echo "$user|policies:$policies|groups:$groups"
  fi
done | tee "$OUTPUT_DIR/admin-users.txt"

echo "--- IAM Roles With Cross-Account Trust ---"
for role in $(aws iam list-roles --query 'Roles[*].RoleName' --output text); do
  trust=$(aws iam get-role --role-name "$role" \
    --query 'Role.AssumeRolePolicyDocument' --output json 2>/dev/null)
  if echo "$trust" | grep -q '"AWS"' && echo "$trust" | grep -qv "$(aws sts get-caller-identity --query Account --output text)"; then
    echo "$role: $trust" | jq -c '.Statement[].Principal'
  fi
done | tee "$OUTPUT_DIR/cross-account-roles.txt"

echo "--- Service Accounts (Programmatic Only) ---"
aws iam get-credential-report --output text --query Content | base64 -d | \ <!-- security-allowlist: doc
