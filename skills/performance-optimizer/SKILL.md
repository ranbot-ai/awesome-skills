---
name: performance-optimizer
description: Identifies and fixes performance bottlenecks in code, databases, and APIs. Measures before and after to prove improvements. 
category: Document Processing
source: antigravity
tags: [javascript, react, node, api, ai, design, document, image, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/performance-optimizer
---


# Performance Optimizer

Find and fix performance bottlenecks. Measure, optimize, verify. Make it fast.

## When to Use This Skill

- App is slow or laggy
- User complains about performance
- Page load times are high
- API responses are slow
- Database queries take too long
- User mentions "slow", "lag", "performance", or "optimize"

## The Optimization Process

### 1. Measure First

Never optimize without measuring:

```javascript
// Measure execution time
console.time('operation');
await slowOperation();
console.timeEnd('operation'); // operation: 2341ms
```

**What to measure:**
- Page load time
- API response time
- Database query time
- Function execution time
- Memory usage
- Network requests

### 2. Find the Bottleneck

Use profiling tools to find the slow parts:

**Browser:**
```
DevTools → Performance tab → Record → Stop
Look for long tasks (red bars)
```

**Node.js:**
```bash
node --prof app.js
node --prof-process isolate-*.log > profile.txt
```

**Database:**
```sql
EXPLAIN ANALYZE SELECT * FROM users WHERE email = 'test@example.com';
```

### 3. Optimize

Fix the slowest thing first (biggest impact).

## Common Optimizations

### Database Queries

**Problem: N+1 Queries**
```javascript
// Bad: N+1 queries
const users = await db.users.find();
for (const user of users) {
  user.posts = await db.posts.find({ userId: user.id }); // N queries
}

// Good: Single query with JOIN
const users = await db.users.find()
  .populate('posts'); // 1 query
```

**Problem: Missing Index**
```sql
-- Check slow query
EXPLAIN SELECT * FROM users WHERE email = 'test@example.com';
-- Shows: Seq Scan (bad)

-- Add index
CREATE INDEX idx_users_email ON users(email);

-- Check again
EXPLAIN SELECT * FROM users WHERE email = 'test@example.com';
-- Shows: Index Scan (good)
```

**Problem: SELECT ***
```javascript
// Bad: Fetches all columns
const users = await db.query('SELECT * FROM users');

// Good: Only needed columns
const users = await db.query('SELECT id, name, email FROM users');
```

**Problem: No Pagination**
```javascript
// Bad: Returns all records
const users = await db.users.find();

// Good: Paginated
const users = await db.users.find()
  .limit(20)
  .skip((page - 1) * 20);
```

### API Performance

**Problem: No Caching**
```javascript
// Bad: Hits database every time
app.get('/api/stats', async (req, res) => {
  const stats = await db.stats.calculate(); // Slow
  res.json(stats);
});

// Good: Cache for 5 minutes
const cache = new Map();
app.get('/api/stats', async (req, res) => {
  const cached = cache.get('stats');
  if (cached && Date.now() - cached.time < 300000) {
    return res.json(cached.data);
  }
  
  const stats = await db.stats.calculate();
  cache.set('stats', { data: stats, time: Date.now() });
  res.json(stats);
});
```

**Problem: Sequential Operations**
```javascript
// Bad: Sequential (slow)
const user = await getUser(id);
const posts = await getPosts(id);
const comments = await getComments(id);
// Total: 300ms + 200ms + 150ms = 650ms

// Good: Parallel (fast)
const [user, posts, comments] = await Promise.all([
  getUser(id),
  getPosts(id),
  getComments(id)
]);
// Total: max(300ms, 200ms, 150ms) = 300ms
```

**Problem: Large Payloads**
```javascript
// Bad: Returns everything
res.json(users); // 5MB response

// Good: Only needed fields
res.json(users.map(u => ({
  id: u.id,
  name: u.name,
  email: u.email
}))); // 500KB response
```

### Frontend Performance

**Problem: Unnecessary Re-renders**
```javascript
// Bad: Re-renders on every parent update
function UserList({ users }) {
  return users.map(user => <UserCard user={user} />);
}

// Good: Memoized
const UserCard = React.memo(({ user }) => {
  return <div>{user.name}</div>;
});
```

**Problem: Large Bundle**
```javascript
// Bad: Imports entire library
import _ from 'lodash'; // 70KB

// Good: Import only what you need
import debounce from 'lodash/debounce'; // 2KB
```

**Problem: No Code Splitting**
```javascript
// Bad: Everything in one bundle
import HeavyComponent from './HeavyComponent';

// Good: Lazy load
const HeavyComponent = React.lazy(() => import('./HeavyComponent'));
```

**Problem: Unoptimized Images**
```html
<!-- Bad: Large image -->
<img src="photo.jpg" /> <!-- 5MB -->

<!-- Good: Optimized and responsive -->
<img 
  src="photo-small.webp" 
  srcset="photo-small.webp 400w, photo-large.webp 800w"
  loading="lazy"
  width="400"
  height="300"
/> <!-- 50KB -->
```

### Algorithm Optimization

**Problem: Inefficient Algorithm**
```javascript
// Bad: O(n²) - nested loops
function findDuplicates(arr) {
  const duplicates = [];
  for (let i = 0; i < arr.length; i++) {
    for (let j = i + 1; j < arr.length; j++) {
      if (arr[i] === arr[j]) duplicates.push(arr[i]);
    }
  }
  return duplicates;
}

// Good: O(n) - single pass with Set
function findDuplicates(arr) {
  const seen = new Set();
  const duplicates = new Set();
  for (const item of arr) {
    if (seen.has(item)) duplicates.add(item);
    seen.add(item);
 
