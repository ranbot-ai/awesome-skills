---
name: notion-meeting-intelligence
description: Prepares meeting materials by gathering context from Notion, enriching with Claude research, and creating both an internal pre-read and external agenda saved to Notion. Helps you arrive prepared with 
category: Productivity & Organization
source: awesome-llm
tags: [claude, ai, workflow, template, design, notion, meeting, intelligence]
url: https://github.com/Prat011/awesome-llm-skills/tree/master/notion-meeting-intelligence
---


# Meeting Intelligence

Prepares you for meetings by gathering context from Notion, enriching it with Claude research, and creating comprehensive meeting materials. Generates both an internal pre-read for attendees and an external-facing agenda for the meeting itself.

## Quick Start

When asked to prep for a meeting:

1. **Gather Notion context**: Use `Notion:notion-search` to find related pages
2. **Fetch details**: Use `Notion:notion-fetch` to read relevant content
3. **Enrich with research**: Use Claude's knowledge to add context, industry insights, or best practices
4. **Create internal pre-read**: Use `Notion:notion-create-pages` for background context document (for attendees)
5. **Create external agenda**: Use `Notion:notion-create-pages` for meeting agenda (shared with all participants)
6. **Link resources**: Connect both docs to related projects and each other

## Meeting Prep Workflow

### Step 1: Understand meeting context

```
Collect meeting details:
- Meeting topic/title
- Attendees (internal team + external participants)
- Meeting purpose (decision, brainstorm, status update, customer demo, etc.)
- Meeting type (internal only vs. external participants)
- Related project/initiative
- Specific topics to cover
```

### Step 2: Search for Notion context

```
Use Notion:notion-search to find:
- Project pages related to meeting topic
- Previous meeting notes
- Specifications or design docs
- Related tasks or issues
- Recent updates or reports
- Customer/partner information (if applicable)

Search strategies:
- Topic-based: "mobile app redesign"
- Project-scoped: search within project teamspace
- Attendee-created: filter by created_by_user_ids
- Recent updates: use created_date_range filters
```

### Step 3: Fetch and analyze Notion content

```
For each relevant page:
1. Fetch with Notion:notion-fetch
2. Extract key information:
   - Project status and timeline
   - Recent decisions and updates
   - Open questions or blockers
   - Relevant metrics or data
   - Action items from previous meetings
3. Note gaps in information
```

### Step 4: Enrich with Claude research

```
Beyond Notion context, add value through:

For technical meetings:
- Explain complex concepts for broader audience
- Summarize industry best practices
- Provide competitive context
- Suggest discussion frameworks

For customer meetings:
- Research company background (if public info)
- Industry trends relevant to discussion
- Common pain points in their sector
- Best practices for similar customers

For decision meetings:
- Decision-making frameworks
- Risk analysis patterns
- Trade-off considerations
- Implementation best practices

Note: Use general knowledge only - don't fabricate specific facts
```

### Step 5: Create internal pre-read

```
Use Notion:notion-create-pages for internal doc:

Title: "[Meeting Topic] - Pre-Read (Internal)"

Content structure:
- **Meeting Overview**: Date, time, attendees, purpose
- **Background Context**: 
  - What this meeting is about (2-3 sentences)
  - Why it matters (business context)
  - Links to related Notion pages
- **Current Status**: 
  - Where we are now (from Notion content)
  - Recent updates and progress
  - Key metrics or data
- **Context & Insights** (from Claude research):
  - Industry context or best practices
  - Relevant considerations
  - Potential approaches to discuss
- **Key Discussion Points**:
  - Topics that need airtime
  - Open questions to resolve
  - Decisions required
- **What We Need from This Meeting**:
  - Expected outcomes
  - Decisions to make
  - Next steps to define

Audience: Internal attendees only
Purpose: Give team full context and alignment before meeting
```

### Step 6: Create external agenda

```
Use Notion:notion-create-pages for meeting doc:

Title: "[Meeting Topic] - Agenda"

Content structure:
- **Meeting Details**: Date, time, attendees
- **Objective**: Clear meeting goal (1-2 sentences)
- **Agenda Items** (with time allocations):
  1. Topic 1 (10 min)
  2. Topic 2 (20 min)
  3. Topic 3 (15 min)
- **Discussion Topics**: 
  - Key items to cover
  - Questions to answer
- **Decisions Needed**: 
  - Clear decision points
- **Action Items**: 
  - (To be filled during meeting)
- **Related Resources**:
  - Links to relevant pages
  - Link to pre-read document

Audience: All participants (internal + external)
Purpose: Structure the meeting, keep it on track
Tone: Professional, focused, clear
```

See [reference/template-selection-guide.md](reference/template-selection-guide.md) for full templates.

### Step 7: Link documents

```
1. Link pre-read to agenda:
   - Add mention in agenda: "See <mention-page>Pre-Read</mention-page> for background"

2. Link both to project:
   - Update project page with meeting links
   - Add to "Meetings" section

3. Cross-reference:
   - Agenda mentions pre-read for internal attendees
   - Pre-read mentions agenda for meeting structure
```

## Document Types

### Internal Pre-Read (for team)

More comprehensive, internal co
