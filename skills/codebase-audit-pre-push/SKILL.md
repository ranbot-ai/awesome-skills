---
name: codebase-audit-pre-push
description: Deep audit before GitHub push: removes junk files, dead code, security holes, and optimization issues. Checks every file line-by-line for production readiness. 
category: Document Processing
source: antigravity
tags: [javascript, typescript, node, api, ai, design, document, image, security, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/codebase-audit-pre-push
---


# Pre-Push Codebase Audit

As a senior engineer, you're doing the final review before pushing this code to GitHub. Check everything carefully and fix problems as you find them.  

## When to Use This Skill  

- User requests "audit the codebase" or "review before push"  
- Before making the first push to GitHub  
- Before making a repository public  
- Pre-production deployment review  
- User asks to "clean up the code" or "optimize everything"  

## Your Job  

Review the entire codebase file by file. Read the code carefully. Fix issues right away. Don't just note problems—make the necessary changes.  

## Audit Process  

### 1. Clean Up Junk Files  

Start by looking for files that shouldn't be on GitHub:  

**Delete these immediately:**  
- OS files: `.DS_Store`, `Thumbs.db`, `desktop.ini`  
- Logs: `*.log`, `npm-debug.log*`, `yarn-error.log*`  
- Temp files: `*.tmp`, `*.temp`, `*.cache`, `*.swp`  
- Build output: `dist/`, `build/`, `.next/`, `out/`, `.cache/`  
- Dependencies: `node_modules/`, `vendor/`, `__pycache__/`, `*.pyc`  
- IDE files: `.idea/`, `.vscode/` (ask user first), `*.iml`, `.project`  
- Backup files: `*.bak`, `*_old.*`, `*_backup.*`, `*_copy.*`  
- Test artifacts: `coverage/`, `.nyc_output/`, `test-results/`  
- Personal junk: `TODO.txt`, `NOTES.txt`, `scratch.*`, `test123.*`  

**Critical - Check for secrets:**  
- `.env` files (should never be committed)  
- Files containing: `password`, `api_key`, `token`, `secret`, `private_key`  
- `*.pem`, `*.key`, `*.cert`, `credentials.json`, `serviceAccountKey.json`  

If you find secrets in the code, mark it as a CRITICAL BLOCKER.  

### 2. Fix .gitignore  

Check if the `.gitignore` file exists and is thorough. If it’s missing or not complete, update it to include all junk file patterns above. Ensure that `.env.example` exists with keys but no values.  

### 3. Audit Every Source File  

Look through each code file and check:  

**Dead Code (remove immediately):**  
- Commented-out code blocks  
- Unused imports/requires  
- Unused variables (declared but never used)  
- Unused functions (defined but never called)  
- Unreachable code (after `return`, inside `if (false)`)  
- Duplicate logic (same code in multiple places—combine)  

**Code Quality (fix issues as you go):**  
- Vague names: `data`, `info`, `temp`, `thing` → rename to be descriptive  
- Magic numbers: `if (status === 3)` → extract to named constant  
- Debug statements: remove `console.log`, `print()`, `debugger`  
- TODO/FIXME comments: either resolve them or delete them  
- TypeScript `any`: add proper types or explain why `any` is used  
- Use `===` instead of `==` in JavaScript  
- Functions longer than 50 lines: consider splitting  
- Nested code greater than 3 levels: refactor with early returns  

**Logic Issues (critical):**  
- Missing null/undefined checks  
- Array operations on potentially empty arrays  
- Async functions that are not awaited  
- Promises without `.catch()` or try/catch  
- Possibilities for infinite loops  
- Missing `default` in switch statements  

### 4. Security Check (Zero Tolerance)  

**Secrets:** Search for hardcoded passwords, API keys, and tokens. They must be in environment variables.  

**Injection vulnerabilities:**  
- SQL: No string concatenation in queries—use parameterized queries only  
- Command injection: No `exec()` with user-provided input  
- Path traversal: No file paths from user input without validation  
- XSS: No `innerHTML` or `dangerouslySetInnerHTML` with user data  

**Auth/Authorization:**  
- Passwords hashed with bcrypt/argon2 (never MD5 or plain text)  
- Protected routes check for authentication  
- Authorization checks on the server side, not just in the UI  
- No IDOR: verify users own the resources they are accessing  

**Data exposure:**  
- API responses do not leak unnecessary information  
- Error messages do not expose stack traces or database details  
- Pagination is present on list endpoints  

**Dependencies:**  
- Run `npm audit` or an equivalent tool  
- Flag critically outdated or vulnerable packages  

### 5. Scalability Check  

**Database:**  
- N+1 queries: loops with database calls inside → use JOINs or batch queries  
- Missing indexes on WHERE/ORDER BY columns  
- Unbounded queries: add LIMIT or pagination  
- Avoid `SELECT *`: specify columns  

**API Design:**  
- Heavy operations (like email, reports, file processing) → move to a background queue  
- Rate limiting on public endpoints  
- Caching for data that is read frequently  
- Timeouts on external calls  

**Code:**  
- No global mutable state  
- Clean up event listeners (to avoid memory leaks)  
- Stream large files instead of loading them into memory  

### 6. Architecture Check  

**Organization:**  
- Clear folder structure  
- Files are in logical locations  
- No "misc" or "stuff" folders  

**Separation of concerns:**  
- UI layer: only responsible for rendering  
- Business logic: pure functions  
- Data layer: isolated
