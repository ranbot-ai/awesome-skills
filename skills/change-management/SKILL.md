---
name: change-management
description: Implement change management processes. Configure CAB reviews, change windows, and rollback procedures. Use when managing production changes. 
category: Security & Systems
source: antigravity
tags: [markdown, api, ai, agent, automation, workflow, template, document, security, vulnerability]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/change-management
---


# Change Management

Implement structured change management processes covering change classification, CAB workflows, emergency change procedures, and automation for compliance with SOC 2, ITIL, and regulatory frameworks.

## Change Classification

```yaml
change_types:
  standard:
    risk: Low
    approval: Pre-approved (no per-change approval needed)
    lead_time: None (within maintenance window)
    examples:
      - Routine patching within tested patch sets
      - Certificate rotation with established procedure
      - Scaling operations (adding/removing instances within limits)
      - Pre-approved configuration changes
      - Log rotation and archival
    requirements:
      - Change must match an approved Standard Change template
      - Automated testing must pass
      - Documented rollback procedure exists
      - Within defined maintenance window

  normal_low:
    risk: Low
    approval: Peer review (1 approver)
    lead_time: 2 business days
    examples:
      - Non-critical configuration changes
      - Feature flag toggles
      - Documentation updates to production systems
      - Adding monitoring dashboards or alerts

  normal_medium:
    risk: Medium
    approval: Team lead + peer review (2 approvers)
    lead_time: 5 business days
    examples:
      - Application deployments with new features
      - Database schema changes (non-breaking)
      - Network rule modifications
      - Integration endpoint changes
      - Dependency version upgrades

  normal_high:
    risk: High
    approval: CAB review required
    lead_time: 10 business days
    examples:
      - Infrastructure migrations
      - Breaking database schema changes
      - Major version upgrades (OS, runtime, database engine)
      - Changes to authentication or authorization systems
      - Multi-service coordinated deployments
      - Changes affecting data processing or compliance controls

  emergency:
    risk: Variable
    approval: Emergency CAB (minimum 2 approvers from on-call)
    lead_time: None (immediate implementation)
    examples:
      - Security vulnerability remediation (active exploitation)
      - Production outage resolution
      - Data integrity emergency fixes
      - Regulatory compliance deadline fixes
    requirements:
      - Retroactive full documentation within 48 hours
      - Post-implementation review required
      - CAB retroactive review at next meeting
```

## Change Request Template

```yaml
change_request:
  metadata:
    id: "CR-YYYY-NNNN"
    title: ""
    requestor: ""
    date_submitted: ""
    target_date: ""
    change_type: ""  # standard | normal_low | normal_medium | normal_high | emergency

  description:
    summary: "Brief description of the change"
    detailed_description: "Full technical details of what will change"
    business_justification: "Why this change is needed"
    affected_systems: []
    affected_services: []
    affected_users: "Description of user impact"

  risk_assessment:
    risk_level: ""  # low | medium | high
    impact_if_failed: "What happens if the change fails"
    likelihood_of_failure: ""  # low | medium | high
    risk_mitigation: "Steps to reduce risk"
    dependencies: "Other systems or changes this depends on"

  implementation:
    change_window:
      start: ""
      end: ""
      maintenance_window: true
    implementation_steps:
      - step: "Step 1 description"
        responsible: "Person/team"
        estimated_duration: "X minutes"
      - step: "Step 2 description"
        responsible: "Person/team"
        estimated_duration: "X minutes"

  testing:
    pre_change_testing:
      - "Unit tests pass"
      - "Integration tests pass"
      - "Staging deployment verified"
    post_change_verification:
      - "Health check endpoints responding"
      - "Key transactions processing successfully"
      - "No error rate increase in monitoring"
      - "Performance metrics within baseline"

  rollback:
    rollback_plan: "Detailed steps to revert the change"
    rollback_trigger: "Conditions that trigger rollback"
    rollback_estimated_time: "X minutes"
    rollback_steps:
      - "Step 1: Revert deployment to previous version"
      - "Step 2: Verify rollback successful"
      - "Step 3: Notify stakeholders"
    data_rollback: "Describe any data migration rollback needed"

  communication:
    stakeholders_notified: []
    notification_sent_date: ""
    status_page_update: true
    customer_notification_required: false

  approvals:
    technical_reviewer: ""
    technical_approval_date: ""
    security_reviewer: ""
    security_approval_date: ""
    cab_approval_date: ""
    cab_notes: ""

  closure:
    implementation_date: ""
    implementation_result: ""  # success | partial | failed | rolled_back
    post_implementation_review: ""
    lessons_learned: ""
    follow_up_actions: []
```

## CAB Workflow

```yaml
cab_workflow:
  meeting_schedule:
    regular_cab: "Weekly, Thursday 2:00 PM"
    emergency_cab: "On-demand, minimum 2
