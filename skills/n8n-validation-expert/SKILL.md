---
name: n8n-validation-expert
description: Expert guide for interpreting and fixing n8n validation errors. 
category: Document Processing
source: antigravity
tags: [javascript, node, api, mcp, ai, automation, workflow, document, security, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/n8n-validation-expert
---


# n8n Validation Expert

Expert guide for interpreting and fixing n8n validation errors.

## When to Use
- You need to interpret or fix validation errors in an n8n workflow.
- The task involves `missing_required`, `invalid_value`, expression failures, or iterative validate-fix loops.
- You want concrete remediation guidance for workflow validation output.

---

## Validation Philosophy

**Validate early, validate often**

Validation is typically iterative:
- Expect validation feedback loops
- Usually 2-3 validate → fix cycles
- Average: 23s thinking about errors, 58s fixing them

**Key insight**: Validation is an iterative process, not one-shot!

---

## Error Severity Levels

### 1. Errors (Must Fix)
**Blocks workflow execution** - Must be resolved before activation

**Types**:
- `missing_required` - Required field not provided
- `invalid_value` - Value doesn't match allowed options
- `type_mismatch` - Wrong data type (string instead of number)
- `invalid_reference` - Referenced node doesn't exist
- `invalid_expression` - Expression syntax error

**Example**:
```json
{
  "type": "missing_required",
  "property": "channel",
  "message": "Channel name is required",
  "fix": "Provide a channel name (lowercase, no spaces, 1-80 characters)"
}
```

### 2. Warnings (Should Fix)
**Doesn't block execution** - Workflow can be activated but may have issues

**Types**:
- `best_practice` - Recommended but not required
- `deprecated` - Using old API/feature
- `performance` - Potential performance issue

**Example**:
```json
{
  "type": "best_practice",
  "property": "errorHandling",
  "message": "Slack API can have rate limits",
  "suggestion": "Add onError: 'continueRegularOutput' with retryOnFail"
}
```

### 3. Suggestions (Optional)
**Nice to have** - Improvements that could enhance workflow

**Types**:
- `optimization` - Could be more efficient
- `alternative` - Better way to achieve same result

---

## The Validation Loop

### Pattern from Telemetry
**7,841 occurrences** of this pattern:

```
1. Configure node
   ↓
2. validate_node (23 seconds thinking about errors)
   ↓
3. Read error messages carefully
   ↓
4. Fix errors
   ↓
5. validate_node again (58 seconds fixing)
   ↓
6. Repeat until valid (usually 2-3 iterations)
```

### Example
```javascript
// Iteration 1
let config = {
  resource: "channel",
  operation: "create"
};

const result1 = validate_node({
  nodeType: "nodes-base.slack",
  config,
  profile: "runtime"
});
// → Error: Missing "name"

// ⏱️  23 seconds thinking...

// Iteration 2
config.name = "general";

const result2 = validate_node({
  nodeType: "nodes-base.slack",
  config,
  profile: "runtime"
});
// → Error: Missing "text"

// ⏱️  58 seconds fixing...

// Iteration 3
config.text = "Hello!";

const result3 = validate_node({
  nodeType: "nodes-base.slack",
  config,
  profile: "runtime"
});
// → Valid! ✅
```

**This is normal!** Don't be discouraged by multiple iterations.

---

## Validation Profiles

Choose the right profile for your stage:

### minimal
**Use when**: Quick checks during editing

**Validates**:
- Only required fields
- Basic structure

**Pros**: Fastest, most permissive
**Cons**: May miss issues

### runtime (RECOMMENDED)
**Use when**: Pre-deployment validation

**Validates**:
- Required fields
- Value types
- Allowed values
- Basic dependencies

**Pros**: Balanced, catches real errors
**Cons**: Some edge cases missed

**This is the recommended profile for most use cases**

### ai-friendly
**Use when**: AI-generated configurations

**Validates**:
- Same as runtime
- Reduces false positives
- More tolerant of minor issues

**Pros**: Less noisy for AI workflows
**Cons**: May allow some questionable configs

### strict
**Use when**: Production deployment, critical workflows

**Validates**:
- Everything
- Best practices
- Performance concerns
- Security issues

**Pros**: Maximum safety
**Cons**: Many warnings, some false positives

---

## Common Error Types

### 1. missing_required
**What it means**: A required field is not provided

**How to fix**:
1. Use `get_node` to see required fields
2. Add the missing field to your configuration
3. Provide an appropriate value

**Example**:
```javascript
// Error
{
  "type": "missing_required",
  "property": "channel",
  "message": "Channel name is required"
}

// Fix
config.channel = "#general";
```

### 2. invalid_value
**What it means**: Value doesn't match allowed options

**How to fix**:
1. Check error message for allowed values
2. Use `get_node` to see options
3. Update to a valid value

**Example**:
```javascript
// Error
{
  "type": "invalid_value",
  "property": "operation",
  "message": "Operation must be one of: post, update, delete",
  "current": "send"
}

// Fix
config.operation = "post";  // Use valid operation
```

### 3. type_mismatch
**What it means**: Wrong data type for field

**How to fix**:
1. Check expected type in error message
2. Convert value to correct type

**Example**:
```javascript
// Error
{
  "type": "type
