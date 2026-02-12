---
name: zoho-crm-automation
description: Automate Zoho CRM tasks via Rube MCP (Composio): create/update records, search contacts, manage leads, and convert leads. Always search tools first for current schemas. 
category: Development & Code Tools
source: composio
tags: [api, cli, mcp, automation, ai]
url: https://github.com/ComposioHQ/awesome-claude-skills/tree/master/zoho-crm-automation
---


# Zoho CRM Automation via Rube MCP

Automate Zoho CRM operations through Composio's Zoho toolkit via Rube MCP.

**Toolkit docs**: [composio.dev/toolkits/zoho](https://composio.dev/toolkits/zoho)

## Prerequisites

- Rube MCP must be connected (RUBE_SEARCH_TOOLS available)
- Active Zoho CRM connection via `RUBE_MANAGE_CONNECTIONS` with toolkit `zoho`
- Always call `RUBE_SEARCH_TOOLS` first to get current tool schemas

## Setup

**Get Rube MCP**: Add `https://rube.app/mcp` as an MCP server in your client configuration. No API keys needed — just add the endpoint and it works.


1. Verify Rube MCP is available by confirming `RUBE_SEARCH_TOOLS` responds
2. Call `RUBE_MANAGE_CONNECTIONS` with toolkit `zoho`
3. If connection is not ACTIVE, follow the returned auth link to complete Zoho OAuth
4. Confirm connection status shows ACTIVE before running any workflows

## Core Workflows

### 1. Search and Retrieve Records

**When to use**: User wants to find specific CRM records by criteria

**Tool sequence**:
1. `ZOHO_LIST_MODULES` - List available CRM modules [Prerequisite]
2. `ZOHO_GET_MODULE_FIELDS` - Get field definitions for a module [Optional]
3. `ZOHO_SEARCH_ZOHO_RECORDS` - Search records by criteria [Required]
4. `ZOHO_GET_ZOHO_RECORDS` - Get records from a module [Alternative]

**Key parameters**:
- `module`: Module name (e.g., 'Leads', 'Contacts', 'Deals', 'Accounts')
- `criteria`: Search criteria string (e.g., 'Email:equals:john@example.com')
- `fields`: Comma-separated list of fields to return
- `per_page`: Number of records per page
- `page`: Page number for pagination

**Pitfalls**:
- Module names are case-sensitive (e.g., 'Leads' not 'leads')
- Search criteria uses specific syntax: 'Field:operator:value'
- Supported operators: equals, starts_with, contains, not_equal, greater_than, less_than
- Complex criteria use parentheses and AND/OR: '(Email:equals:john@example.com)AND(Last_Name:equals:Doe)'
- GET_ZOHO_RECORDS returns all records with optional filtering; SEARCH is for targeted lookups

### 2. Create Records

**When to use**: User wants to add new leads, contacts, deals, or other CRM records

**Tool sequence**:
1. `ZOHO_GET_MODULE_FIELDS` - Get required fields for the module [Prerequisite]
2. `ZOHO_CREATE_ZOHO_RECORD` - Create a new record [Required]

**Key parameters**:
- `module`: Target module name (e.g., 'Leads', 'Contacts')
- `data`: Record data object with field-value pairs
- Required fields vary by module (e.g., Last_Name for Contacts)

**Pitfalls**:
- Each module has mandatory fields; use GET_MODULE_FIELDS to identify them
- Field names use underscores (e.g., 'Last_Name', 'Email', 'Phone')
- Lookup fields require the related record ID, not the name
- Date fields must use 'yyyy-MM-dd' format
- Creating duplicates is allowed unless duplicate check rules are configured

### 3. Update Records

**When to use**: User wants to modify existing CRM records

**Tool sequence**:
1. `ZOHO_SEARCH_ZOHO_RECORDS` - Find the record to update [Prerequisite]
2. `ZOHO_UPDATE_ZOHO_RECORD` - Update the record [Required]

**Key parameters**:
- `module`: Module name
- `record_id`: ID of the record to update
- `data`: Object with fields to update (only changed fields needed)

**Pitfalls**:
- record_id must be the Zoho record ID (numeric string)
- Only provide fields that need to change; other fields are preserved
- Read-only and system fields cannot be updated
- Lookup field updates require the related record ID

### 4. Convert Leads

**When to use**: User wants to convert a lead into a contact, account, and/or deal

**Tool sequence**:
1. `ZOHO_SEARCH_ZOHO_RECORDS` - Find the lead to convert [Prerequisite]
2. `ZOHO_CONVERT_ZOHO_LEAD` - Convert the lead [Required]

**Key parameters**:
- `lead_id`: ID of the lead to convert
- `deal`: Deal details if creating a deal during conversion
- `account`: Account details for the conversion
- `contact`: Contact details for the conversion

**Pitfalls**:
- Lead conversion is irreversible; the lead record is removed from the Leads module
- Conversion can create up to three records: Contact, Account, and Deal
- Existing account matching may occur based on company name
- Custom field mappings between Lead and Contact/Account/Deal modules affect the outcome

### 5. Manage Tags and Related Records

**When to use**: User wants to tag records or manage relationships between records

**Tool sequence**:
1. `ZOHO_CREATE_ZOHO_TAG` - Create a new tag [Optional]
2. `ZOHO_UPDATE_RELATED_RECORDS` - Update related/linked records [Optional]

**Key parameters**:
- `module`: Module for the tag
- `tag_name`: Name of the tag
- `record_id`: Parent record ID (for related records)
- `related_module`: Module of the related record
- `data`: Related record data to update

**Pitfalls**:
- Tags are module-specific; a tag created for Leads is not available in Contacts
- Related records require both the parent record ID and the related module
- Tag names must be unique within a module
- Bulk tag operations may hit
