---
name: n8n-code-javascript
description: Write JavaScript code in n8n Code nodes. Use when writing JavaScript in n8n, using $input/$json/$node syntax, making HTTP requests with $helpers, working with dates using DateTime, troubleshooting Cod
category: Document Processing
source: antigravity
tags: [python, javascript, node, api, mcp, ai, workflow, template, document, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/n8n-code-javascript
---


# JavaScript Code Node

Expert guidance for writing JavaScript code in n8n Code nodes.

---

## Quick Start

```javascript
// Basic template for Code nodes
const items = $input.all();

// Process data
const processed = items.map(item => ({
  json: {
    ...item.json,
    processed: true,
    timestamp: new Date().toISOString()
  }
}));

return processed;
```

### Essential Rules

1. **Choose "Run Once for All Items" mode** (recommended for most use cases)
2. **Access data**: `$input.all()`, `$input.first()`, or `$input.item`
3. **CRITICAL**: Must return `[{json: {...}}]` format
4. **CRITICAL**: Webhook data is under `$json.body` (not `$json` directly)
5. **Built-ins available**: $helpers.httpRequest(), DateTime (Luxon), $jmespath()

---

## Mode Selection Guide

The Code node offers two execution modes. Choose based on your use case:

### Run Once for All Items (Recommended - Default)

**Use this mode for:** 95% of use cases

- **How it works**: Code executes **once** regardless of input count
- **Data access**: `$input.all()` or `items` array
- **Best for**: Aggregation, filtering, batch processing, transformations, API calls with all data
- **Performance**: Faster for multiple items (single execution)

```javascript
// Example: Calculate total from all items
const allItems = $input.all();
const total = allItems.reduce((sum, item) => sum + (item.json.amount || 0), 0);

return [{
  json: {
    total,
    count: allItems.length,
    average: total / allItems.length
  }
}];
```

**When to use:**
- ✅ Comparing items across the dataset
- ✅ Calculating totals, averages, or statistics
- ✅ Sorting or ranking items
- ✅ Deduplication
- ✅ Building aggregated reports
- ✅ Combining data from multiple items

### Run Once for Each Item

**Use this mode for:** Specialized cases only

- **How it works**: Code executes **separately** for each input item
- **Data access**: `$input.item` or `$item`
- **Best for**: Item-specific logic, independent operations, per-item validation
- **Performance**: Slower for large datasets (multiple executions)

```javascript
// Example: Add processing timestamp to each item
const item = $input.item;

return [{
  json: {
    ...item.json,
    processed: true,
    processedAt: new Date().toISOString()
  }
}];
```

**When to use:**
- ✅ Each item needs independent API call
- ✅ Per-item validation with different error handling
- ✅ Item-specific transformations based on item properties
- ✅ When items must be processed separately for business logic

**Decision Shortcut:**
- **Need to look at multiple items?** → Use "All Items" mode
- **Each item completely independent?** → Use "Each Item" mode
- **Not sure?** → Use "All Items" mode (you can always loop inside)

---

## Data Access Patterns

### Pattern 1: $input.all() - Most Common

**Use when**: Processing arrays, batch operations, aggregations

```javascript
// Get all items from previous node
const allItems = $input.all();

// Filter, map, reduce as needed
const valid = allItems.filter(item => item.json.status === 'active');
const mapped = valid.map(item => ({
  json: {
    id: item.json.id,
    name: item.json.name
  }
}));

return mapped;
```

### Pattern 2: $input.first() - Very Common

**Use when**: Working with single objects, API responses, first-in-first-out

```javascript
// Get first item only
const firstItem = $input.first();
const data = firstItem.json;

return [{
  json: {
    result: processData(data),
    processedAt: new Date().toISOString()
  }
}];
```

### Pattern 3: $input.item - Each Item Mode Only

**Use when**: In "Run Once for Each Item" mode

```javascript
// Current item in loop (Each Item mode only)
const currentItem = $input.item;

return [{
  json: {
    ...currentItem.json,
    itemProcessed: true
  }
}];
```

### Pattern 4: $node - Reference Other Nodes

**Use when**: Need data from specific nodes in workflow

```javascript
// Get output from specific node
const webhookData = $node["Webhook"].json;
const httpData = $node["HTTP Request"].json;

return [{
  json: {
    combined: {
      webhook: webhookData,
      api: httpData
    }
  }
}];
```

**See**: DATA_ACCESS.md for comprehensive guide

---

## Critical: Webhook Data Structure

**MOST COMMON MISTAKE**: Webhook data is nested under `.body`

```javascript
// ❌ WRONG - Will return undefined
const name = $json.name;
const email = $json.email;

// ✅ CORRECT - Webhook data is under .body
const name = $json.body.name;
const email = $json.body.email;

// Or with $input
const webhookData = $input.first().json.body;
const name = webhookData.name;
```

**Why**: Webhook node wraps all request data under `body` property. This includes POST data, query parameters, and JSON payloads.

**See**: DATA_ACCESS.md for full webhook structure details

---

## Return Format Requirements

**CRITICAL RULE**: Always return array of objects with `json` property

### Correct Return Formats

```javascript
// ✅ Single result
return [{
  json: {
    field1: value1,
    field2: value2
  }
}];
