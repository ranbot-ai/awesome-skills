---
name: cypress-skill
description: Generates production-grade Cypress E2E and component tests in JavaScript or TypeScript. Supports local execution and TestMu AI cloud. Use when the user asks to write Cypress tests, set up Cypress, tes
category: Creative & Media
source: antigravity
tags: [javascript, typescript, react, node, pdf, api, ai, agent, automation, workflow]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/cypress-skill
---


# Cypress Automation Skill
## When to Use

Use this skill when you need generates production-grade Cypress E2E and component tests in JavaScript or TypeScript. Supports local execution and TestMu AI cloud. Use when the user asks to write Cypress tests, set up Cypress, test with cy commands, or mentions "Cypress", "cy.visit", "cy.get", "cy.intercept"....


You are a senior QA automation architect specializing in Cypress.

## Step 1 — Execution Target

```
User says "test" / "automate"
│
├─ Mentions "cloud", "TestMu", "LambdaTest", "cross-browser"?
│  └─ TestMu AI cloud via cypress-cli plugin
│
├─ Mentions "locally", "open", "headed"?
│  └─ Local: npx cypress open
│
└─ Ambiguous? → Default local, mention cloud option
```

## Step 2 — Test Type

| Signal | Type | Config |
|--------|------|--------|
| "E2E", "end-to-end", page URL | E2E test | `cypress/e2e/` |
| "component", "React", "Vue" | Component test | `cypress/component/` |
| "API test", "cy.request" | API test via Cypress | `cypress/e2e/api/` |

## Core Patterns

### Command Chaining — CRITICAL

```javascript
// ✅ Cypress chains — no await, no async
cy.visit('/login');
cy.get('#username').type('user@test.com');
cy.get('#password').type('password123');
cy.get('button[type="submit"]').click();
cy.url().should('include', '/dashboard');

// ❌ NEVER use async/await with cy commands
// ❌ NEVER assign cy.get() to a variable for later use
```

### Selector Priority

```
1. cy.get('[data-cy="submit"]')     ← Best practice
2. cy.get('[data-testid="submit"]') ← Also good
3. cy.contains('Submit')            ← Text-based
4. cy.get('#submit-btn')            ← ID
5. cy.get('.btn-primary')           ← Class (fragile)
```

### Anti-Patterns

| Bad | Good | Why |
|-----|------|-----|
| `cy.wait(5000)` | `cy.intercept()` + `cy.wait('@alias')` | Arbitrary waits |
| `const el = cy.get()` | Chain directly | Cypress is async |
| `async/await` with cy | Chain `.then()` if needed | Different async model |
| Testing 3rd party sites | Stub/mock instead | Flaky, slow |
| Single `beforeEach` with everything | Multiple focused specs | Better isolation |

### Basic Test Structure

```javascript
describe('Login', () => {
  beforeEach(() => {
    cy.visit('/login');
  });

  it('should login with valid credentials', () => {
    cy.get('[data-cy="username"]').type('user@test.com');
    cy.get('[data-cy="password"]').type('password123');
    cy.get('[data-cy="submit"]').click();
    cy.url().should('include', '/dashboard');
    cy.get('[data-cy="welcome"]').should('contain', 'Welcome');
  });

  it('should show error for invalid credentials', () => {
    cy.get('[data-cy="username"]').type('wrong@test.com');
    cy.get('[data-cy="password"]').type('wrong');
    cy.get('[data-cy="submit"]').click();
    cy.get('[data-cy="error"]').should('be.visible');
  });
});
```

### Network Interception

```javascript
// Stub API response
cy.intercept('POST', '/api/login', {
  statusCode: 200,
  body: { token: 'fake-jwt', user: { name: 'Test User' } },
}).as('loginRequest');

cy.get('[data-cy="submit"]').click();
cy.wait('@loginRequest').its('request.body').should('deep.include', {
  email: 'user@test.com',
});

// Wait for real API
cy.intercept('GET', '/api/dashboard').as('dashboardLoad');
cy.visit('/dashboard');
cy.wait('@dashboardLoad');
```

### Custom Commands

```javascript
// cypress/support/commands.js
Cypress.Commands.add('login', (email, password) => {
  cy.session([email, password], () => {
    cy.visit('/login');
    cy.get('[data-cy="username"]').type(email);
    cy.get('[data-cy="password"]').type(password);
    cy.get('[data-cy="submit"]').click();
    cy.url().should('include', '/dashboard');
  });
});

// Usage in tests
cy.login('user@test.com', 'password123');
```

### TestMu AI Cloud

```javascript
// cypress.config.js
module.exports = {
  e2e: {
    setupNodeEvents(on, config) {
      // LambdaTest plugin
    },
  },
};

// lambdatest-config.json
{
  "lambdatest_auth": {
    "username": "${LT_USERNAME}",
    "access_key": "${LT_ACCESS_KEY}"
  },
  "browsers": [
    { "browser": "Chrome", "platform": "Windows 11", "versions": ["latest"] },
    { "browser": "Firefox", "platform": "macOS Sequoia", "versions": ["latest"] }
  ],
  "run_settings": {
    "build_name": "Cypress Build",
    "parallels": 5,
    "specs": "cypress/e2e/**/*.cy.js"
  }
}
```

**Run on cloud:**
```bash
npx lambdatest-cypress run
```

## Validation Workflow

1. **No arbitrary waits**: Zero `cy.wait(number)` — use intercepts
2. **Selectors**: Prefer `data-cy` attributes
3. **No async/await**: Pure Cypress chaining
4. **Assertions**: Use `.should()` chains, not manual checks
5. **Isolation**: Each test independent, use `cy.session()` for auth

## Quick Reference

| Task | Command |
|------|---------|
| Open interactive | `npx cypress open` |
| Run headless | `npx cypress run` |
| Run specific spec | `npx cypress run --spec "cypress/e2e/login.cy.js"` |
| Run in browser | `npx cypress run --browser chrome` |
| Compo
