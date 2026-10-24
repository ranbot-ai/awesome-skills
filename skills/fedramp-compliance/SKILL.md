---
name: fedramp-compliance
description: Implement FedRAMP requirements for federal cloud services. Configure NIST 800-53 controls and continuous monitoring. Use when providing cloud services to US federal agencies. 
category: Security & Systems
source: antigravity
tags: [markdown, ai, agent, template, design, document, spreadsheet, image, security, vulnerability]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/fedramp-compliance
---


# FedRAMP Compliance

Implement FedRAMP (Federal Risk and Authorization Management Program) requirements for cloud service providers serving US federal agencies.

## When to Use

- Pursuing FedRAMP authorization for a cloud service offering
- Implementing NIST 800-53 security controls for federal workloads
- Establishing continuous monitoring (ConMon) processes
- Managing Plan of Action and Milestones (POA&M) tracking
- Preparing for a Third-Party Assessment Organization (3PAO) audit
- Operating a FedRAMP-authorized system and maintaining authorization

## Resolve the Applicable Program First

This is an illustrative Rev5 evidence-planning guide, not a current certification checklist. Record the service boundary, agency customers, selected Rev5 or 20x path, class, rule version and effective date before mapping controls. In the 2026 transition, FedRAMP uses certification and Classes A–D terminology; the timeline permits early adoption before January 2027 mandatory adoption, with area-specific effective dates. Legacy Low/Moderate/High labels below provide historical context only. Do not select a category from a data-type example alone: assess confidentiality, integrity and availability impact with the responsible agency and current rules.

Use the current official baseline and templates, not the illustrative subset below. JAB P-ATO is not a required route for High systems; JAB authorizations transitioned to the single FedRAMP designation. An agency’s authorization to operate remains a separate decision.

## Historical Impact Labels (Illustrative)

```yaml
impact_levels:
  low:
    baseline: "Resolve current applicable official baseline"
    use_case: "Publicly available federal information"
    examples:
      - Public-facing websites with no sensitive data
      - Open data portals
      - Marketing and informational systems
    data_types: "No PII, no CUI, publicly releasable only"
    path: "Resolve current program/class and eligibility"

  moderate:
    baseline: "Resolve current applicable official baseline"
    use_case: "Most federal systems, including CUI"
    examples:
      - Email and collaboration platforms
      - Case management systems
      - Financial management systems
      - HR and personnel systems
    data_types: "CUI, PII, law enforcement sensitive (LES)"
    path: "Resolve current program/class and eligibility"

  high:
    baseline: "Resolve current applicable official baseline"
    use_case: "High-impact federal systems"
    examples:
      - Law enforcement and criminal justice systems
      - Emergency services and public safety
      - Financial systems with significant impact
      - Healthcare systems with PHI
    data_types: "Unclassified high-impact federal information; classified systems require a separate regime"
    path: "Resolve current program/class and eligibility"
```

## NIST 800-53 Control Families

```yaml
control_families:
  AC:
    name: "Access Control"
    key_controls:
      AC-2: "Account Management - manage system accounts lifecycle"
      AC-3: "Access Enforcement - enforce approved authorizations"
      AC-6: "Least Privilege - employ principle of least privilege"
      AC-17: "Remote Access - establish usage restrictions for remote access"
    implementation_notes: "Map to IAM policies, RBAC, MFA enforcement"

  AU:
    name: "Audit and Accountability"
    key_controls:
      AU-2: "Audit Events - define auditable events"
      AU-3: "Content of Audit Records - ensure records contain required info"
      AU-6: "Audit Review, Analysis, and Reporting"
      AU-12: "Audit Generation - generate audit records"
    implementation_notes: "Map to CloudTrail, CloudWatch Logs, SIEM"

  AT:
    name: "Awareness and Training"
    key_controls:
      AT-2: "Security Awareness Training - provide training to users"
      AT-3: "Role-Based Security Training - for personnel with security roles"
    implementation_notes: "Annual security training, role-specific training"

  CM:
    name: "Configuration Management"
    key_controls:
      CM-2: "Baseline Configuration - develop and maintain baseline"
      CM-6: "Configuration Settings - establish mandatory settings"
      CM-7: "Least Functionality - restrict to essential capabilities"
      CM-8: "Information System Component Inventory"
    implementation_notes: "Map to AWS Config, SSM, hardened AMIs"

  CP:
    name: "Contingency Planning"
    key_controls:
      CP-2: "Contingency Plan - develop and maintain plan"
      CP-4: "Contingency Plan Testing - test plan annually"
      CP-9: "Information System Backup"
      CP-10: "Information System Recovery and Reconstitution"
    implementation_notes: "Map to DR plan, backup strategy, failover testing"

  IA:
    name: "Identification and Authentication"
    key_controls:
      IA-2: "Identification and Authentication (Org Users)"
      IA-5: "Authenticator Management"
      IA-8: "Identification and Authentication (Non-Org Users)"
    implementation_notes: "Map to SSO, MF
