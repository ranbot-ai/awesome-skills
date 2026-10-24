---
name: dependency-upgrade
description: Master major dependency version upgrades, compatibility analysis, staged upgrade strategies, and comprehensive testing approaches. 
category: Document Processing
source: antigravity
tags: [javascript, typescript, react, markdown, api, ai, llm, document, image, security]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/dependency-upgrade
---

## Supporting material availability

This catalog copy contains the inline guidance below, but does not include the following supporting paths. They are external prerequisites, not bundled files:

- `<support-root>/references/semver.md`
- `<support-root>/references/compatibility-matrix.md`
- `<support-root>/references/staged-upgrades.md`
- `<support-root>/references/testing-strategy.md`
- `<support-root>/assets/upgrade-checklist.md`
- `<support-root>/assets/compatibility-matrix.csv`
- `<support-root>/scripts/audit-dependencies.sh`

Ask for the original supporting material or an existing installation before using a step that depends on these paths; this catalog does not identify a verified download source for them. Resolve each path relative to that installation, inspect its contents, and verify any applicable license and execution prerequisites. Do not run a command or claim a referenced procedure was followed until its required file exists. Do not fabricate the missing scripts or treat an unrelated file with the same name as equivalent. Independent steps fully documented here can proceed within the user’s authorized scope; report any dependent step as unavailable.


# Dependency Upgrade

Master major dependency version upgrades, compatibility analysis, staged upgrade strategies, and comprehensive testing approaches.

## Do not use this skill when

- The task is unrelated to dependency upgrade
- You need a different domain or tool outside this scope

## Instructions

- Clarify goals, constraints, and required inputs.
- Apply relevant best practices and validate outcomes.
- Provide actionable steps and verification.

## Use this skill when

- Upgrading major framework versions
- Updating security-vulnerable dependencies
- Modernizing legacy dependencies
- Resolving dependency conflicts
- Planning incremental upgrade paths
- Testing compatibility matrices
- Automating dependency updates

## Semantic Versioning Review

```
MAJOR.MINOR.PATCH (e.g., 2.3.1)

MAJOR: Breaking changes
MINOR: New features, backward compatible
PATCH: Bug fixes, backward compatible

^2.3.1 = >=2.3.1 <3.0.0 (minor updates)
~2.3.1 = >=2.3.1 <2.4.0 (patch updates)
2.3.1 = exact version
```

Separate inspection from mutation: npm audit fix/dedupe, yarn dedupe and ncu -u change dependency state. Pin and review codemods/CLI packages before running; the changelog-parser/react-codeshift command shapes below are illustrative and must be checked against the actual official tool, not assumed runnable. Regex migration is not syntax-aware and can corrupt strings/comments/imports; use reviewed AST transforms and inspect every diff. SemVer promises do not prove compatibility and caret rules differ below 1.0. Select exact targets from release notes/peer requirements instead of latest. --force/--legacy-peer-deps bypass protections rather than resolve incompatibility. A matching React version or DOM snapshot is not full runtime/visual verification. Do not overwrite an existing UPGRADE_PLAN.md or enable automerge implicitly.

## Dependency Analysis

### Audit Dependencies
```bash
# npm
npm outdated
npm audit
npm audit fix

# yarn
yarn outdated
yarn audit

# Check for major updates
npx npm-check-updates
npx npm-check-updates -u  # Update package.json
```

### Analyze Dependency Tree
```bash
# See why a package is installed
npm ls package-name
yarn why package-name

# Find duplicate packages
npm dedupe
yarn dedupe

# Visualize dependencies
npx madge --image graph.png src/
```

## Compatibility Matrix

```javascript
// compatibility-matrix.js
const compatibilityMatrix = {
  'react': {
    '16.x': {
      'react-dom': '^16.0.0',
      'react-router-dom': '^5.0.0',
      '@testing-library/react': '^11.0.0'
    },
    '17.x': {
      'react-dom': '^17.0.0',
      'react-router-dom': '^5.0.0 || ^6.0.0',
      '@testing-library/react': '^12.0.0'
    },
    '18.x': {
      'react-dom': '^18.0.0',
      'react-router-dom': '^6.0.0',
      '@testing-library/react': '^13.0.0'
    }
  }
};

function checkCompatibility(packages) {
  // Validate package versions against matrix
}
```

## Staged Upgrade Strategy

### Phase 1: Planning
```bash
# 1. Identify current versions
npm list --depth=0

# 2. Check for breaking changes
# Read CHANGELOG.md and MIGRATION.md

# 3. Create upgrade plan
echo "Upgrade order:
1. TypeScript
2. React
3. React Router
4. Testing libraries
5. Build tools" > UPGRADE_PLAN.md
```

### Phase 2: Incremental Updates
```bash
# Don't upgrade everything at once!

# Step 1: Update TypeScript
npm install typescript@latest

# Test
npm run test
npm run build

# Step 2: Update React (one major version at a time)
npm install react@17 react-dom@17

# Test again
npm run test

# Step 3: Continue with other packages
npm install react-router-dom@6

# And so on...
```

### Phase 3: Validation
```javascript
// tests/compatibility.test.js
describe('Dependency Compatibility', () => {
  it('should have compatible React versions', () => {
    const reactVersion = require
