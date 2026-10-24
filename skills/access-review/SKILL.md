---
name: access-review
description: Conduct periodic access reviews and certifications. Implement access governance and recertification workflows. Use when managing access compliance. 
category: Document Processing
source: antigravity
tags: [python, markdown, api, ai, agent, llm, automation, workflow, template, document]
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

## Review boundaries

Confirm exact tenant/accounts, read-only credentials, review period and authorized
reviewers. Store reports privately with defined retention; proposed cadence/SLA
numbers are examples, not compliance certification. Identity joins need verified
immutable IDs, not matching display names. Owner approval and a recovery/break-glass
plan are required before modifying access; inactivity heuristics never authorize
revoking production service accounts automatically.

## AWS IAM Access Review Scripts

Obtain the IAM credential report through a read-only scoped client, poll boundedly
until complete, and decode it once into a private file. Failure/unsupported values
are unknown, never zero/inactive. Use named CSV columns, not positional awk fields:

```python
import csv

def review_console_mfa(report_path):
    candidates = []
    with open(report_path, newline="", encoding="utf-8") as source:
        for row in csv.DictReader(source):
            if row.get("password_enabled") == "true" and row.get("mfa_active") == "false":
                candidates.append({"user": row["user"], "finding": "review_console_mfa"})
    return candidates  # Private review data, not automatic disable actions.
```

Compare timezone-aware last-use/creation times and both access-key slots with an
agreed threshold; missing history may mean never-used, unsupported or unavailable.
Password last-use alone is not overall account inactivity. Effective privilege
requires user/group/role/inline policies, boundaries, SCPs and resource policies;
policy-name matching is only a hint. Cross-account trust needs structured principal
and condition analysis, not grep or an AWS-account substring. No key or access is
revoked solely because a report marks it stale.

## GitHub Access Review

```bash
#!/usr/bin/env bash
# github-access-review.sh - Partial organization inventory
set -euo pipefail
umask 077

ORG="your-org"
OUTPUT_DIR="./access-review/github/$(date +%Y-%m)"
mkdir -p "$OUTPUT_DIR"

echo "=== GitHub Organization Access Review ==="

echo "--- Organization Members ---"
gh api orgs/$ORG/members --paginate \
  --jq '.[] | [.login, .site_admin] | @csv' \
  > "$OUTPUT_DIR/org-members.csv"

echo "--- Organization Owners ---"
gh api "orgs/$ORG/members?role=admin" --paginate \
  --jq '.[] | .login' \
  > "$OUTPUT_DIR/org-owners.txt"

echo "--- Outside Collaborators ---"
gh api orgs/$ORG/outside_collaborators --paginate \
  --jq '.[] | .login' \
  > "$OUTPUT_DIR/outside-collaborators.txt"

echo "--- Repository Access Per Repo ---"
for repo in $(gh api "orgs/$ORG/repos" --paginate --jq '.[].name'); do
  echo "Repo: $repo"
  gh api "repos/$ORG/$repo/collaborators" --paginate \
    --jq '.[] | [.login, .role_name] | @csv' \
    > "$OUTPUT_DIR/repo-$repo-access.csv"
done

echo "--- Team Memberships ---"
for team in $(gh api orgs/$ORG/teams --paginate --jq '.[].slug'); do
  echo "Team: $team"
  gh api "orgs/$ORG/teams/$team/members" --paginate \
    --jq '.[] | .login' \
    > "$OUTPUT_DIR/tea
