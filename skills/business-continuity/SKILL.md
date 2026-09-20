---
name: business-continuity
description: Develop business continuity plans and impact analysis. Implement BCP testing and communication procedures. Use when building organizational resilience. 
category: Document Processing
source: antigravity
tags: [markdown, api, ai, agent, llm, template, design, document, presentation, security]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/business-continuity
---


# Business Continuity Planning

Develop and maintain business continuity capabilities including Business Impact Analysis, communication plans, recovery procedures, and testing schedules for organizational resilience.

## When to Use

- Developing a formal Business Continuity Plan (BCP) for the organization
- Conducting a Business Impact Analysis (BIA) to prioritize recovery efforts
- Establishing communication plans for crisis scenarios
- Defining recovery procedures for critical business processes
- Scheduling and conducting BCP exercises and tests
- Meeting compliance requirements for continuity planning (SOC 2, ISO 27001, HIPAA, FedRAMP)

## BCP Framework

```yaml
bcp_phases:
  1_governance:
    actions:
      - Obtain executive sponsorship and funding
      - Assign BCP coordinator and team
      - Define BCP scope and policy
      - Establish BCP committee with cross-functional representation
    deliverables:
      - BCP policy statement
      - BCP team charter and roster
      - Scope document

  2_analysis:
    actions:
      - Conduct Business Impact Analysis (BIA)
      - Perform risk assessment for continuity threats
      - Identify critical business processes and dependencies
      - Determine recovery priorities and resource requirements
    deliverables:
      - BIA report
      - Risk assessment report
      - Critical process inventory

  3_strategy:
    actions:
      - Select recovery strategies for each critical process
      - Identify alternate work arrangements (remote, alternate site)
      - Define technology recovery strategies (DR plan)
      - Establish vendor and supply chain contingencies
    deliverables:
      - Recovery strategy document
      - Technology recovery plan
      - Alternate site arrangements

  4_plan_development:
    actions:
      - Write detailed recovery procedures
      - Develop communication plans (internal and external)
      - Create emergency response procedures
      - Document roles, responsibilities, and contact information
    deliverables:
      - Business Continuity Plan document
      - Communication plan
      - Emergency response procedures
      - Contact lists and call trees

  5_testing:
    actions:
      - Develop test plan and schedule
      - Conduct exercises (tabletop, functional, full-scale)
      - Evaluate results and identify gaps
      - Update plans based on lessons learned
    deliverables:
      - Test plan
      - Exercise reports
      - Updated BCP based on findings

  6_maintenance:
    actions:
      - Review and update BCP annually (minimum)
      - Update after significant organizational changes
      - Refresh BIA when business processes change
      - Maintain training and awareness program
    deliverables:
      - Annual BCP review record
      - Updated BIA (if changes occurred)
      - Training completion records
```

## Business Impact Analysis Template

```yaml
bia_template:
  process_assessment:
    process_name: ""
    process_owner: ""
    department: ""
    description: ""

    criticality_classification:
      mission_critical:
        max_tolerable_downtime: "0-4 hours"
        description: "Failure causes immediate, severe impact to customers or revenue"
        examples:
          - Payment processing
          - Authentication and authorization
          - Core API serving customer requests
          - Order fulfillment

      essential:
        max_tolerable_downtime: "4-24 hours"
        description: "Failure causes significant degradation but not complete loss"
        examples:
          - Customer support systems
          - Reporting and dashboards
          - Email and notifications
          - Billing and invoicing

      important:
        max_tolerable_downtime: "1-3 days"
        description: "Failure causes inconvenience and workarounds are available"
        examples:
          - Internal collaboration tools
          - Analytics and BI platforms
          - HR self-service systems
          - Knowledge base

      non_essential:
        max_tolerable_downtime: "3-7 days"
        description: "Failure has minimal operational impact"
        examples:
          - Development and test environments
          - Training platforms
          - Archive systems

    impact_categories:
      financial:
        revenue_loss_per_hour: ""
        penalty_or_fine_risk: ""
        recovery_cost_estimate: ""

      operational:
        affected_employees: ""
        affected_customers: ""
        workaround_available: "yes/no"
        workaround_description: ""

      reputational:
        customer_visibility: "high/medium/low"
        media_attention_risk: "high/medium/low"
        regulatory_reporting_required: "yes/no"

      legal_regulatory:
        compliance_impact: ""
        contractual_sla_breach: "yes/no"
        sla_penalty_details: ""

    dependencies:
      technology:
        - system: ""
          rto: ""
          rpo: ""
          dr_strategy: ""
      people:
        - role: ""
    
