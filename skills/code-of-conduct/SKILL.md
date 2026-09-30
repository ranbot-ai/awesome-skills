---
name: code-of-conduct
description: Build a human-reviewed conduct register after context-first intake. Use when an SME needs policy acknowledgements, complaint handling, and breach follow-up. 
category: Document Processing
source: antigravity
tags: [pdf, markdown, ai, workflow, template, design, document, spreadsheet, presentation, security]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/code-of-conduct
---


# Professional Code of Conduct

**What it is:** the professional conduct policy the business runs on, and the register that
records who has read it, who has been trained, what was reported, what was investigated,
and what was followed up.

## Overview

Works out the smallest useful conduct policy for the business in front of it, then builds
it only when asked. The default output is a short recommendation, not a policy document. The
acknowledgement and breach register - CSV, SQL DDL, JSON Schema, Notion mapping - is
produced on request, from one field list so the four cannot drift apart.

Layer: Layer 7: Protect. Fits: Starter stage. Table code: n/a.

**The rule this table exists to enforce:** a code of conduct is not a document, it is a
promise that people can be held to. That requires three separate things kept apart in the
register: that someone was **given** the policy, that they **understood** it, and that a
report is **investigated** and **followed up**. A ticked acknowledgement that only means a
PDF was opened is not a third of anything - it is nothing.

**The second rule, and the one that is not negotiable:** a person is never judged by this
skill. Investigation, findings, sanctions and sign-off are human decisions made under the
business's own procedure and applicable law. The register records that a step happened and
who did it. It never records a conclusion.

## When to Use This Skill

- code of conduct, workplace policy, ethics policy, values and behaviour
- professional standards, expected behaviour, acceptable use
- staff handbook section on conduct
- complaint, grievance, misconduct, breach, warning
- policy acknowledgement, training record, sign-off sheet
- "our staff are not professional", "customers complained about behaviour"
- contractor, supplier and partner conduct expectations

Do not use it for: the disciplinary process itself, which belongs to
`disciplinary-pip-tracker` in the operational pack; a formal legal drafting task; or
investigation, adjudication or any decision about a person.

## How It Works

Follow the shared execution contract. The module-specific rules below define only domain fields, decisions, calculations, and safety constraints.

### Step 1 - Identify intent

Read the request and pick the intent before asking anything.

- "write" / "set up" / "we need" -> artifacts wanted; go to Step 2.
- "we have one" / "review" / "is this ok" -> a check, not a build.
- "someone complained" / "what do we do" -> an incident, not a policy question. Answer from
  the business's procedure, escalate to a human, and do not build anything.
- "a breach happened" / "handle" -> a case. This skill does not handle cases.

Ask only if this is the highest-value missing fact; otherwise proceed without an opener:

> **Q:** How many people work in the business, and does it have any employees at all yet?

### Step 2 - Ask only what is missing

Treat ambiguous replies as unanswered and ask which explicit option the user means. Record unknown values as `Unknown`; `Unknown` is not zero. A record must not be `Done` when a required check fails.

Skip anything already answered. Ask the rest one at a time, and stop as soon as the
remaining answers would not change the policy.

- **People** - How many employees, and are there contractors, interns or agency staff? /
  Are any in a regulated profession? / Is anyone in a union or covered by a collective
  agreement?
- **Setting** - Office, site, retail floor, remote, or mixed? / Does anyone work with
  children, vulnerable adults, or handle money, medication or data?
- **Rules** - Any existing employee handbook, or HR provider? / Any sector code, licensing
  body or accreditation with its own conduct rules? / Any written disciplinary procedure
  already in place?
- **Law** - Which country are the employees in? / Has anyone advised on what employment law
  requires - notice, right to be accompanied, right to appeal?
- **Practical** - Who receives a complaint, and who is independent enough to investigate?
  / How is a breach recorded today, if at all? / Does the business want the policy to cover
  social media and personal conduct outside work?

Never invent an answer. Employee names, roles, jurisdictions, legal references, union
names, awarding bodies and disciplinary outcomes the user has not supplied are `Unknown`.
This skill never supplies legal text.

### Step 3 - Hold the internal context

```yaml
module: code-of-conduct
intent: null            # set up | review | report | import
scale: null             # Starter | Growth | Scale, only if the answer changes it
areas:
  "People": null
  "Setting": null
  "Rules": null
  "Law": null
  "Practical": null
requested_outputs: []
confirmed_facts: []
open_questions: []
```

### Step 4 - Recommend the smallest workflow

Build an already requested artifact without asking again. For advice-only requests, give a short recommendation and offer the relevant artifact.

**Recommended approach:** A two-page policy that a p
