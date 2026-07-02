---
name: changelog-updates
description: Create release notes and product updates that developers actually read and care about. This skill covers changelog formatting, versioning communication, breaking change announcements, deprecation noti
category: Document Processing
source: antigravity
tags: [python, markdown, api, ai, workflow, template, document, security, rag, marketing]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/changelog-updates
---


# Changelogs and Product Updates Developers Care About
## When to Use

Use this skill when you need create release notes and product updates that developers actually read and care about. This skill covers changelog formatting, versioning communication, breaking change announcements, deprecation notices, and building anticipation for new features. Trigger phrases: "changelog",...


Release notes are developer communication, not documentation. When done well, they build trust, demonstrate momentum, and turn updates into marketing moments.

## Overview

Changelogs serve multiple audiences and purposes:
- **Active developers**: "What changed that affects my integration?"
- **Evaluating developers**: "Is this product actively maintained?"
- **Developer advocates**: "What's worth sharing with my audience?"
- **Your team**: Historical record of what shipped and when

This skill covers creating changelogs that inform, build trust, and occasionally delight.

## Before You Start

Review the **developer-audience-context** skill to understand:
- How do your developers prefer to receive updates?
- What changes do they care most about?
- How much detail do they need?
- What's their tolerance for breaking changes?

Your changelog tone and detail level should match your audience.

## Changelog Format

### The Standard Structure

```markdown
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]
### Added
- New feature in development

## [2.3.0] - 2024-01-15
### Added
- New `analyze()` method for sentiment analysis
- Support for batch processing up to 100 items

### Changed
- Improved error messages with troubleshooting links
- Default timeout increased from 30s to 60s

### Deprecated
- `old_analyze()` will be removed in v3.0.0

### Fixed
- Race condition in concurrent requests (#234)
- Memory leak when processing large files (#256)

## [2.2.1] - 2024-01-08
### Fixed
- Critical security patch for authentication bypass

## [2.2.0] - 2024-01-01
...
```

### Change Categories

| Category | Use For |
|----------|---------|
| **Added** | New features, new endpoints, new parameters |
| **Changed** | Behavior changes, performance improvements |
| **Deprecated** | Features being phased out (still working) |
| **Removed** | Features that no longer exist |
| **Fixed** | Bug fixes |
| **Security** | Security-related changes |

### Good vs. Bad Entries

**Good Changelog Entries:**
```markdown
### Added
- New `batch_analyze()` method processes up to 100 items in a single
  request, reducing API calls by 90% for bulk operations.
  [See docs](https://github.com/jonathimer/devmarketing-skills/tree/main/skills/changelog-updates/link) (#198)

### Fixed
- Fixed timeout errors when processing files larger than 10MB.
  Uploads now stream in chunks, eliminating memory issues. (#234)

### Deprecated
- `legacy_auth()` will be removed in v3.0.0 (scheduled for March 2024).
  Migrate to `oauth_auth()` using our [migration guide](https://github.com/jonathimer/devmarketing-skills/tree/main/skills/changelog-updates/link).
```

**Bad Changelog Entries:**
```markdown
### Added
- New feature

### Fixed
- Fixed bug
- Fixed another bug
- Various improvements

### Changed
- Updated dependencies
```

### Writing Style

**Be specific:**
```
❌ "Improved performance"
✅ "Reduced API response time by 40% for list operations"
```

**Include context:**
```
❌ "Fixed issue #234"
✅ "Fixed timeout errors when uploading large files (#234)"
```

**Link to resources:**
```
✅ "New batch API - [documentation](https://github.com/jonathimer/devmarketing-skills/tree/main/skills/changelog-updates/link) | [migration guide](https://github.com/jonathimer/devmarketing-skills/tree/main/skills/changelog-updates/link)"
```

**Explain impact:**
```
✅ "Breaking: `user_id` parameter renamed to `id`.
    Update your code before upgrading."
```

## What to Include

### Always Include

**API Changes:**
- New endpoints
- New parameters
- Changed response formats
- Changed error codes

**SDK Changes:**
- New methods
- Changed method signatures
- New configuration options

**Breaking Changes:**
- Anything that requires code changes
- Removed features
- Changed defaults

**Security Fixes:**
- Even if vague, acknowledge security updates
- Follow responsible disclosure timeline

### Consider Including

**Performance Improvements:**
```markdown
### Changed
- List operations now 3x faster through pagination optimization
```

**Developer Experience:**
```markdown
### Added
- Error messages now include troubleshooting links
- SDK now validates API keys at initialization
```

**Infrastructure:**
```markdown
### Changed
- New data center in EU (eu-west.api.example.com)
- Increased rate limits from 100 to 500 requests/minute
```

### Skip or Minimize

**Internal refactoring:**
```markdown
❌ "Refactored authentication m
