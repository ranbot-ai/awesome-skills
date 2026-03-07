---
name: api-endpoint-builder
description: Builds production-ready REST API endpoints with validation, error handling, authentication, and documentation. Follows best practices for security and scalability. 
category: Document Processing
source: antigravity
tags: [javascript, node, api, ai, template, design, document, security]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/api-endpoint-builder
---


# API Endpoint Builder

Build complete, production-ready REST API endpoints with proper validation, error handling, authentication, and documentation.

## When to Use This Skill

- User asks to "create an API endpoint" or "build a REST API"
- Building new backend features
- Adding endpoints to existing APIs
- User mentions "API", "endpoint", "route", or "REST"
- Creating CRUD operations

## What You'll Build

For each endpoint, you create:
- Route handler with proper HTTP method
- Input validation (request body, params, query)
- Authentication/authorization checks
- Business logic
- Error handling
- Response formatting
- API documentation
- Tests (if requested)

## Endpoint Structure

### 1. Route Definition

```javascript
// Express example
router.post('/api/users', authenticate, validateUser, createUser);

// Fastify example
fastify.post('/api/users', {
  preHandler: [authenticate],
  schema: userSchema
}, createUser);
```

### 2. Input Validation

Always validate before processing:

```javascript
const validateUser = (req, res, next) => {
  const { email, name, password } = req.body;
  
  if (!email || !email.includes('@')) {
    return res.status(400).json({ error: 'Valid email required' });
  }
  
  if (!name || name.length < 2) {
    return res.status(400).json({ error: 'Name must be at least 2 characters' });
  }
  
  if (!password || password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  }
  
  next();
};
```

### 3. Handler Implementation

```javascript
const createUser = async (req, res) => {
  try {
    const { email, name, password } = req.body;
    
    // Check if user exists
    const existing = await db.users.findOne({ email });
    if (existing) {
      return res.status(409).json({ error: 'User already exists' });
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Create user
    const user = await db.users.create({
      email,
      name,
      password: hashedPassword,
      createdAt: new Date()
    });
    
    // Don't return password
    const { password: _, ...userWithoutPassword } = user;
    
    res.status(201).json({
      success: true,
      data: userWithoutPassword
    });
    
  } catch (error) {
    console.error('Create user error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};
```

## Best Practices

### HTTP Status Codes
- `200` - Success (GET, PUT, PATCH)
- `201` - Created (POST)
- `204` - No Content (DELETE)
- `400` - Bad Request (validation failed)
- `401` - Unauthorized (not authenticated)
- `403` - Forbidden (not authorized)
- `404` - Not Found
- `409` - Conflict (duplicate)
- `500` - Internal Server Error

### Response Format

Consistent structure:

```javascript
// Success
{
  "success": true,
  "data": { ... }
}

// Error
{
  "error": "Error message",
  "details": { ... } // optional
}

// List with pagination
{
  "success": true,
  "data": [...],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 100
  }
}
```

### Security Checklist

- [ ] Authentication required for protected routes
- [ ] Authorization checks (user owns resource)
- [ ] Input validation on all fields
- [ ] SQL injection prevention (use parameterized queries)
- [ ] Rate limiting on public endpoints
- [ ] No sensitive data in responses (passwords, tokens)
- [ ] CORS configured properly
- [ ] Request size limits set

### Error Handling

```javascript
// Centralized error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  
  // Don't leak error details in production
  const message = process.env.NODE_ENV === 'production' 
    ? 'Internal server error' 
    : err.message;
  
  res.status(err.status || 500).json({ error: message });
});
```

## Common Patterns

### CRUD Operations

```javascript
// Create
POST /api/resources
Body: { name, description }

// Read (list)
GET /api/resources?page=1&limit=20

// Read (single)
GET /api/resources/:id

// Update
PUT /api/resources/:id
Body: { name, description }

// Delete
DELETE /api/resources/:id
```

### Pagination

```javascript
const getResources = async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 20;
  const skip = (page - 1) * limit;
  
  const [resources, total] = await Promise.all([
    db.resources.find().skip(skip).limit(limit),
    db.resources.countDocuments()
  ]);
  
  res.json({
    success: true,
    data: resources,
    pagination: {
      page,
      limit,
      total,
      pages: Math.ceil(total / limit)
    }
  });
};
```

### Filtering & Sorting

```javascript
const getResources = async (req, res) => {
  const { status, sort = '-createdAt' } = req.query;
  
  const filter = {};
  if (status) filter.status = status;
  
  const resources = await db.resources
    .find(filter)
    .sort(sort)
    .limit(20);
  
  res.json({ success: true, data: resources });
};
```

## Documentation Template

```javasc
