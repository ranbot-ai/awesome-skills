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

## Impact Levels

```yaml
impact_levels:
  low:
    control_count: ~125
    use_case: "Publicly available federal information"
    examples:
      - Public-facing websites with no sensitive data
      - Open data portals
      - Marketing and informational systems
    data_types: "No PII, no CUI, publicly releasable only"
    authorization_path: "FedRAMP Tailored (Li-SaaS) or standard Low"

  moderate:
    control_count: ~325
    use_case: "Most federal systems, including CUI"
    examples:
      - Email and collaboration platforms
      - Case management systems
      - Financial management systems
      - HR and personnel systems
    data_types: "CUI, PII, law enforcement sensitive (LES)"
    authorization_path: "Agency or JAB P-ATO"
    note: "~80% of FedRAMP authorizations are at Moderate"

  high:
    control_count: ~425
    use_case: "High-impact federal systems"
    examples:
      - Law enforcement and criminal justice systems
      - Emergency services and public safety
      - Financial systems with significant impact
      - Healthcare systems with PHI
    data_types: "Classified-adjacent, life-safety, critical infrastructure"
    authorization_path: "JAB P-ATO required"
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
    implementation_notes: "Map to SSO, MFA, certificate-based auth, PIV/CAC"

  IR:
    name: "Incident Response"
    key_controls:
      IR-2: "Incident Response Training"
      IR-4: "Incident Handling - implement incident handling capability"
      IR-6: "Incident Reporting - report incidents to US-CERT"
      IR-8: "Incident Response Plan"
    implementation_notes: "US-CERT reporting within 1 hour for federal incidents"

  MA:
    name: "Maintenance"
    key_controls:
      MA-2: "Controlled Maintenance"
      MA-4: "Nonlocal Maintenance - authorize nonlocal maintenance"
    implementation_notes: "Patching procedures, remote maintenance controls"

  MP:
    name: "Media Protection"
    key_controls:
      MP-2: "Media Access - restrict access to media"
      MP-6: "Media Sanitization - sanitize media prior to disposal"
    implementation_notes: "Encryption at rest, secure disposal procedures"

  PE:
    name: "Physical and Environmental Protection"
    key_controls:
      PE-2: "Physical Access Authorizations"
      PE-3: "Physical Access Control"
      PE-6: "Monitoring Physical Access"
    implementation_notes:
