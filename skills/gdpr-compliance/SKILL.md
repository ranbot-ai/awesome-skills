---
name: gdpr-compliance
description: Implement GDPR data protection requirements. Configure consent management, data subject rights, and privacy by design. Use when processing EU personal data. 
category: Document Processing
source: antigravity
tags: [python, markdown, api, ai, agent, automation, workflow, template, design, document]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/gdpr-compliance
---


# GDPR Compliance

Implement General Data Protection Regulation requirements for organizations that process personal data of EU/EEA residents, covering lawful processing, data subject rights, and technical safeguards.

## Key Principles and Legal Bases

```yaml
gdpr_principles:
  article_5:
    lawfulness_fairness_transparency:
      description: "Process data lawfully, fairly, and transparently"
      implementation:
        - Document legal basis for every processing activity
        - Provide clear privacy notices
        - No hidden or deceptive data collection

    purpose_limitation:
      description: "Collect for specified, explicit, and legitimate purposes"
      implementation:
        - Define purpose before collection
        - Do not repurpose data without new legal basis
        - Document all processing purposes in ROPA

    data_minimization:
      description: "Adequate, relevant, and limited to what is necessary"
      implementation:
        - Collect only required fields
        - Review data models for unnecessary fields
        - Remove optional fields that are not used

    accuracy:
      description: "Accurate and kept up to date"
      implementation:
        - Provide self-service profile editing
        - Implement data validation at point of entry
        - Schedule regular data quality reviews

    storage_limitation:
      description: "Kept no longer than necessary"
      implementation:
        - Define retention periods per data category
        - Automate deletion when retention expires
        - Document retention schedule

    integrity_and_confidentiality:
      description: "Appropriate security measures"
      implementation:
        - Encryption at rest and in transit
        - Access controls and audit logging
        - Pseudonymization where appropriate

    accountability:
      description: "Demonstrate compliance"
      implementation:
        - Maintain Records of Processing Activities
        - Conduct DPIAs for high-risk processing
        - Appoint DPO if required

legal_bases:
  article_6:
    consent: "Freely given, specific, informed, unambiguous"
    contract: "Necessary for performance of a contract"
    legal_obligation: "Required by EU or member state law"
    vital_interests: "Protect life of data subject or another person"
    public_interest: "Task carried out in public interest"
    legitimate_interest: "Legitimate interest not overridden by data subject rights"
```

## Data Mapping Template (Records of Processing Activities)

```yaml
# Record of Processing Activities (ROPA) - Article 30
processing_activity:
  name: "Customer Account Management"
  controller: "Example Corp, 123 Main St, Dublin, Ireland"
  dpo_contact: "dpo@example.com"
  purpose: "Manage customer accounts, provide services, handle billing"
  legal_basis: "Contract (Art. 6(1)(b))"
  categories_of_data_subjects:
    - Customers
    - Prospective customers
  categories_of_personal_data:
    - Name, email, phone number
    - Billing address
    - Payment information (tokenized)
    - Service usage data
    - Support ticket history
  special_categories: "None"
  recipients:
    - Payment processor (Stripe) - processor
    - Email service (SendGrid) - processor
    - Cloud hosting (AWS) - processor
  international_transfers:
    - Destination: United States
      Safeguard: "Standard Contractual Clauses (SCCs)"
      TIA_completed: true
  retention_period: "Account data retained for duration of contract + 7 years for legal obligations"
  security_measures:
    - AES-256 encryption at rest
    - TLS 1.3 in transit
    - Role-based access control
    - Audit logging of all access
  dpia_required: false
  last_reviewed: "2024-06-01"

# Template for each processing activity
processing_activity_template:
  name: ""
  controller: ""
  joint_controller: ""  # if applicable
  processor: ""  # if acting as processor
  dpo_contact: ""
  purpose: ""
  legal_basis: ""  # consent | contract | legal_obligation | vital_interests | public_interest | legitimate_interest
  legitimate_interest_assessment: ""  # if legitimate interest
  categories_of_data_subjects: []
  categories_of_personal_data: []
  special_categories: ""  # Art. 9 data
  recipients: []
  international_transfers: []
  retention_period: ""
  security_measures: []
  dpia_required: false
  date_added: ""
  last_reviewed: ""
```

## Consent Management Implementation

```python
"""
Consent management system implementing GDPR Article 7 requirements.
Consent must be freely given, specific, informed, and unambiguous.
"""
from datetime import datetime, timezone
from enum import Enum
import json
import hashlib


class ConsentPurpose(Enum):
    MARKETING_EMAIL = "marketing_email"
    MARKETING_SMS = "marketing_sms"
    ANALYTICS = "analytics"
    PERSONALIZATION = "personalization"
    THIRD_PARTY_SHARING = "third_party_sharing"
    PROFILING = "profiling"


class ConsentManager:
    def __init__(self, db):
        self.db = db

    def record_c
