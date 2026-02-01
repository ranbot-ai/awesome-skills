---
name: n8n-node-configuration
description: Operation-aware node configuration guidance. Use when configuring nodes, understanding property dependencies, determining required fields, choosing between get_node detail levels, or learning common c
category: AI & Agents
source: antigravity
tags: [javascript, node, api, mcp, ai, workflow, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/n8n-node-configuration
---


# n8n Node Configuration

Expert guidance for operation-aware node configuration with property dependencies.

## When to Use This Skill

Use this skill when:
- Configuring n8n nodes
- Understanding property dependencies
- Determining required fields
- Choosing between get_node detail levels
- Learning common configuration patterns by node type

---

## Configuration Philosophy

**Progressive disclosure**: Start minimal, add complexity as needed

Configuration best practices:
- `get_node` with `detail: "standard"` is the most used discovery pattern
- 56 seconds average between configuration edits
- Covers 95% of use cases with 1-2K tokens response

**Key insight**: Most configurations need only standard detail, not full schema!

---

## Core Concepts

### 1. Operation-Aware Configuration

**Not all fields are always required** - it depends on operation!

**Example**: Slack node
```javascript
// For operation='post'
{
  "resource": "message",
  "operation": "post",
  "channel": "#general",  // Required for post
  "text": "Hello!"        // Required for post
}

// For operation='update'
{
  "resource": "message",
  "operation": "update",
  "messageId": "123",     // Required for update (different!)
  "text": "Updated!"      // Required for update
  // channel NOT required for update
}
```

**Key**: Resource + operation determine which fields are required!

### 2. Property Dependencies

**Fields appear/disappear based on other field values**

**Example**: HTTP Request node
```javascript
// When method='GET'
{
  "method": "GET",
  "url": "https://api.example.com"
  // sendBody not shown (GET doesn't have body)
}

// When method='POST'
{
  "method": "POST",
  "url": "https://api.example.com",
  "sendBody": true,       // Now visible!
  "body": {               // Required when sendBody=true
    "contentType": "json",
    "content": {...}
  }
}
```

**Mechanism**: displayOptions control field visibility

### 3. Progressive Discovery

**Use the right detail level**:

1. **get_node({detail: "standard"})** - DEFAULT
   - Quick overview (~1-2K tokens)
   - Required fields + common options
   - **Use first** - covers 95% of needs

2. **get_node({mode: "search_properties", propertyQuery: "..."})** (for finding specific fields)
   - Find properties by name
   - Use when looking for auth, body, headers, etc.

3. **get_node({detail: "full"})** (complete schema)
   - All properties (~3-8K tokens)
   - Use only when standard detail is insufficient

---

## Configuration Workflow

### Standard Process

```
1. Identify node type and operation
   ↓
2. Use get_node (standard detail is default)
   ↓
3. Configure required fields
   ↓
4. Validate configuration
   ↓
5. If field unclear → get_node({mode: "search_properties"})
   ↓
6. Add optional fields as needed
   ↓
7. Validate again
   ↓
8. Deploy
```

### Example: Configuring HTTP Request

**Step 1**: Identify what you need
```javascript
// Goal: POST JSON to API
```

**Step 2**: Get node info
```javascript
const info = get_node({
  nodeType: "nodes-base.httpRequest"
});

// Returns: method, url, sendBody, body, authentication required/optional
```

**Step 3**: Minimal config
```javascript
{
  "method": "POST",
  "url": "https://api.example.com/create",
  "authentication": "none"
}
```

**Step 4**: Validate
```javascript
validate_node({
  nodeType: "nodes-base.httpRequest",
  config,
  profile: "runtime"
});
// → Error: "sendBody required for POST"
```

**Step 5**: Add required field
```javascript
{
  "method": "POST",
  "url": "https://api.example.com/create",
  "authentication": "none",
  "sendBody": true
}
```

**Step 6**: Validate again
```javascript
validate_node({...});
// → Error: "body required when sendBody=true"
```

**Step 7**: Complete configuration
```javascript
{
  "method": "POST",
  "url": "https://api.example.com/create",
  "authentication": "none",
  "sendBody": true,
  "body": {
    "contentType": "json",
    "content": {
      "name": "={{$json.name}}",
      "email": "={{$json.email}}"
    }
  }
}
```

**Step 8**: Final validation
```javascript
validate_node({...});
// → Valid! ✅
```

---

## get_node Detail Levels

### Standard Detail (DEFAULT - Use This!)

**✅ Starting configuration**
```javascript
get_node({
  nodeType: "nodes-base.slack"
});
// detail="standard" is the default
```

**Returns** (~1-2K tokens):
- Required fields
- Common options
- Operation list
- Metadata

**Use**: 95% of configuration needs

### Full Detail (Use Sparingly)

**✅ When standard isn't enough**
```javascript
get_node({
  nodeType: "nodes-base.slack",
  detail: "full"
});
```

**Returns** (~3-8K tokens):
- Complete schema
- All properties
- All nested options

**Warning**: Large response, use only when standard insufficient

### Search Properties Mode

**✅ Looking for specific field**
```javascript
get_node({
  nodeType: "nodes-base.httpRequest",
  mode: "search_properties",
  propertyQuery: "auth"
});
```

**Use**: Find authentication, headers, body fields, etc.

### Decision 
