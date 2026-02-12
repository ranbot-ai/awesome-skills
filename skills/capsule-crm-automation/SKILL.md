---
name: Capsule CRM Automation
description: Automate Capsule CRM operations -- manage contacts (parties), run structured filter queries, track tasks and projects, log entries, and handle organizations -- using natural language through the Compo
category: Development & Code Tools
source: composio
tags: [api, cli, mcp, automation, ai]
url: https://github.com/ComposioHQ/awesome-claude-skills/tree/master/capsule-crm-automation
---


# Capsule CRM Automation

Manage your Capsule CRM -- create and update contacts, run powerful filter queries on parties/opportunities/cases, track tasks and projects, browse activity entries, and organize team relationships -- all through natural language commands.

**Toolkit docs:** [composio.dev/toolkits/capsule_crm](https://composio.dev/toolkits/capsule_crm)

---

## Setup

1. Add the Composio MCP server to your client configuration:
   ```
   https://rube.app/mcp
   ```
2. Connect your Capsule CRM account when prompted (OAuth authentication).
3. Start issuing natural language commands to manage your CRM.

---

## Core Workflows

### 1. Run Structured Filter Queries
Query parties, opportunities, or cases (projects) with multiple filter conditions, operators, and sorting.

**Tool:** `CAPSULE_CRM_RUN_FILTER_QUERY`

**Example prompt:**
> "Find all Capsule CRM contacts in California tagged as 'VIP' sorted by name"

**Key parameters:**
- `entity` (required) -- One of: `parties`, `opportunities`, `kases`
- `filter` (required) -- Filter object with:
  - `conditions` -- Array of conditions, each with:
    - `field` -- Field name (e.g., "name", "email", "state", "country", "tag", "owner", "jobTitle", "addedOn")
    - `operator` -- One of: "is", "is not", "starts with", "ends with", "contains", "is greater than", "is less than", "is after", "is before", "is older than", "is within last", "is within next"
    - `value` -- Value to compare against
  - `orderBy` -- Array of sort objects with `field` and `direction` ("ascending"/"descending")
- `embed` -- Additional data to include in response
- `page` / `perPage` -- Pagination (max 100 per page)

**Important field notes:**
- Address fields (`city`, `state`, `country`, `zip`) are top-level, NOT nested under "address"
- Country must be an ISO 3166-1 alpha-2 code (e.g., "US", "GB", "CA")
- Custom fields use `custom:{fieldId}` format
- Organization fields use `org.` prefix (e.g., `org.name`, `org.tag`)

---

### 2. List and Manage Contacts (Parties)
Retrieve all contacts with optional filtering by modification date and embedded related data.

**Tool:** `CAPSULE_CRM_LIST_PARTIES`

**Example prompt:**
> "List all Capsule CRM contacts modified since January 2025 with their tags and organizations"

**Key parameters:**
- `since` -- ISO8601 date to filter contacts changed after this date
- `embed` -- Additional data: "tags", "fields", "organisation", "missingImportantFields"
- `page` / `perPage` -- Pagination (max 100 per page, default 50)

---

### 3. Create New Contacts
Add people or organizations to your Capsule CRM with full details including emails, phones, addresses, tags, and custom fields.

**Tool:** `CAPSULE_CRM_CREATE_PARTY`

**Example prompt:**
> "Create a new person in Capsule CRM: John Smith, VP of Sales at Acme Corp, john@acme.com"

**Key parameters:**
- `type` (required) -- "person" or "organisation"
- For persons: `firstName`, `lastName`, `jobTitle`, `title`
- For organisations: `name`
- `emailAddresses` -- Array of `{address, type}` objects
- `phoneNumbers` -- Array of `{number, type}` objects
- `addresses` -- Array of address objects with `street`, `city`, `state`, `country`, `zip`, `type` (Home/Postal/Office/Billing/Shipping)
- `organisation` -- Link to org by `{id}` or `{name}` (creates if not found)
- `tags` -- Array of tags by `{name}` or `{id}`
- `fields` -- Custom field values with `{definition, value}`
- `websites` -- Array of `{address, service, type}` objects
- `owner` -- Assign owner user `{id}`

---

### 4. Update Existing Contacts
Modify any aspect of a party record including adding/removing emails, phones, tags, and custom fields.

**Tool:** `CAPSULE_CRM_UPDATE_PARTY`

**Example prompt:**
> "Update Capsule CRM party 11587: add a work email john.new@acme.com and remove tag 'prospect'"

**Key parameters:**
- `partyId` (required) -- Integer ID of the party to update
- `party` (required) -- Object with fields to update. Supports:
  - All creation fields (name, emails, phones, addresses, etc.)
  - `_delete: true` on sub-items to remove them (requires the item's `id`)
  - Tags: add by `{name}` or remove with `{id, _delete: true}`

---

### 5. Track Tasks
List tasks with filtering by status and embedded related data.

**Tool:** `CAPSULE_CRM_LIST_TASKS`

**Example prompt:**
> "Show all open tasks in Capsule CRM with their linked parties and owners"

**Key parameters:**
- `status` -- Filter by status: "open", "completed", "pending" (array)
- `embed` -- Additional data: "party", "opportunity", "kase", "owner", "nextTask"
- `page` / `perPage` -- Pagination (max 100 per page, default 50)

---

### 6. Browse Projects and Activity Entries
List projects (cases) and recent activity entries including notes, emails, and completed tasks.

**Tools:** `CAPSULE_CRM_LIST_PROJECTS`, `CAPSULE_CRM_LIST_ENTRIES_BY_DATE`

**Example prompt:**
> "Show all open projects in Capsule CRM" / "Show recent activity entries with party details"

**Key parameters for projects:**
- `st
