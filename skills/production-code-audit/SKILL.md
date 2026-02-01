---
name: production-code-audit
description: Autonomously deep-scan entire codebase line-by-line, understand architecture and patterns, then systematically transform it to production-grade, corporate-level professional quality with optimizations
category: Security & Systems
source: antigravity
tags: [typescript, react, node, markdown, api, ai, workflow, template, design, document]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/production-code-audit
---


# Production Code Audit

## Overview

Autonomously analyze the entire codebase to understand its architecture, patterns, and purpose, then systematically transform it into production-grade, corporate-level professional code. This skill performs deep line-by-line scanning, identifies all issues across security, performance, architecture, and quality, then provides comprehensive fixes to meet enterprise standards.

## When to Use This Skill

- Use when user says "make this production-ready"
- Use when user says "audit my codebase"
- Use when user says "make this professional/corporate-level"
- Use when user says "optimize everything"
- Use when user wants enterprise-grade quality
- Use when preparing for production deployment
- Use when code needs to meet corporate standards

## How It Works

### Step 1: Autonomous Codebase Discovery

**Automatically scan and understand the entire codebase:**

1. **Read all files** - Scan every file in the project recursively
2. **Identify tech stack** - Detect languages, frameworks, databases, tools
3. **Understand architecture** - Map out structure, patterns, dependencies
4. **Identify purpose** - Understand what the application does
5. **Find entry points** - Locate main files, routes, controllers
6. **Map data flow** - Understand how data moves through the system

**Do this automatically without asking the user.**

### Step 2: Comprehensive Issue Detection

**Scan line-by-line for all issues:**

**Architecture Issues:**
- Circular dependencies
- Tight coupling
- God classes (>500 lines or >20 methods)
- Missing separation of concerns
- Poor module boundaries
- Violation of design patterns

**Security Vulnerabilities:**
- SQL injection (string concatenation in queries)
- XSS vulnerabilities (unescaped output)
- Hardcoded secrets (API keys, passwords in code)
- Missing authentication/authorization
- Weak password hashing (MD5, SHA1)
- Missing input validation
- CSRF vulnerabilities
- Insecure dependencies

**Performance Problems:**
- N+1 query problems
- Missing database indexes
- Synchronous operations that should be async
- Missing caching
- Inefficient algorithms (O(n²) or worse)
- Large bundle sizes
- Unoptimized images
- Memory leaks

**Code Quality Issues:**
- High cyclomatic complexity (>10)
- Code duplication
- Magic numbers
- Poor naming conventions
- Missing error handling
- Inconsistent formatting
- Dead code
- TODO/FIXME comments

**Testing Gaps:**
- Missing tests for critical paths
- Low test coverage (<80%)
- No edge case testing
- Flaky tests
- Missing integration tests

**Production Readiness:**
- Missing environment variables
- No logging/monitoring
- No error tracking
- Missing health checks
- Incomplete documentation
- No CI/CD pipeline

### Step 3: Automatic Fixes and Optimizations

**Fix everything automatically:**

1. **Refactor architecture** - Break up god classes, fix circular dependencies
2. **Fix security issues** - Use parameterized queries, remove secrets, add validation
3. **Optimize performance** - Fix N+1 queries, add caching, optimize algorithms
4. **Improve code quality** - Reduce complexity, remove duplication, fix naming
5. **Add missing tests** - Write tests for untested critical paths
6. **Add production infrastructure** - Logging, monitoring, health checks
7. **Optimize everything** - Bundle size, images, database queries
8. **Add documentation** - README, API docs, architecture docs

### Step 4: Verify and Report

**After making all changes:**

1. Run all tests to ensure nothing broke
2. Verify all security issues are fixed
3. Measure performance improvements
4. Generate comprehensive report
5. Provide before/after metrics

## Examples

### Example 1: Autonomous Codebase Transformation

```markdown
User: @production-code-audit make this production-ready

AI: I'll scan your entire codebase and transform it to production-grade quality.

**Phase 1: Discovering Codebase** (analyzing 247 files)
- Detected: Node.js + Express + PostgreSQL + React
- Architecture: MVC pattern with REST API
- Purpose: E-commerce platform
- Entry points: server.js, src/index.tsx

**Phase 2: Scanning for Issues** (line-by-line analysis)

Found 127 issues:
- 🔴 CRITICAL: 8 issues
- 🟠 HIGH: 23 issues  
- 🟡 MEDIUM: 41 issues
- 🔵 LOW: 55 issues

**Phase 3: Fixing Issues Automatically**

🔴 CRITICAL FIXES (8/8 completed):

1. ✅ Fixed SQL injection in UserRepository.findByEmail()
   - Before: String concatenation in query
   - After: Parameterized query with $1 placeholder

2. ✅ Removed hardcoded database password from config/database.ts
   - Before: password: 'SuperSecret123!'
   - After: password: process.env.DB_PASSWORD

3. ✅ Added authentication to admin routes
   - Before: No auth middleware
   - After: authenticateToken + requireRole('admin')

4. ✅ Fixed weak password hashing (MD5 → bcrypt)
   - Before: crypto.createHash('md5')
   - After: bcrypt.hash(password, 12)

5. ✅ Fixed circular dependency: OrderService ↔ PaymentService
   - Before: Direct imports caus
