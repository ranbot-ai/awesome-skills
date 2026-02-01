---
name: screenshots
description: Generate marketing screenshots of your app using Playwright. Use when the user wants to create screenshots for Product Hunt, social media, landing pages, or documentation. 
category: Document Processing
source: antigravity
tags: [javascript, react, node, ai, template, document, image, rag, cro, marketing]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/screenshots
---


# Screenshots

Generate marketing-quality screenshots of your app using Playwright directly. Screenshots are captured at true HiDPI (2x retina) resolution using `deviceScaleFactor: 2`.

## When to Use This Skill

Use this skill when:
- User wants to create screenshots for Product Hunt
- Creating screenshots for social media
- Generating images for landing pages
- Creating documentation screenshots
- User requests marketing-quality app screenshots

## Prerequisites

Playwright must be available. Check for it:
```bash
npx playwright --version 2>/dev/null || npm ls playwright 2>/dev/null | grep playwright
```

If not found, inform the user:
> Playwright is required. Install it with: `npm install -D playwright` or `npm install -D @playwright/test`

## Step 1: Determine App URL

If `$1` is provided, use it as the app URL.

If no URL is provided:
1. Check if a dev server is likely running by looking for `package.json` scripts
2. Use `AskUserQuestion` to ask the user for the URL or offer to help start the dev server

Common default URLs to suggest:
- `http://localhost:3000` (Next.js, Create React App, Rails)
- `http://localhost:5173` (Vite)
- `http://localhost:4000` (Phoenix)
- `http://localhost:8080` (Vue CLI, generic)

## Step 2: Gather Requirements

Use `AskUserQuestion` with the following questions:

**Question 1: Screenshot count**
- Header: "Count"
- Question: "How many screenshots do you need?"
- Options:
  - "3-5" - Quick set of key features
  - "5-10" - Comprehensive feature coverage
  - "10+" - Full marketing suite

**Question 2: Purpose**
- Header: "Purpose"
- Question: "What will these screenshots be used for?"
- Options:
  - "Product Hunt" - Hero shots and feature highlights
  - "Social media" - Eye-catching feature demos
  - "Landing page" - Marketing sections and benefits
  - "Documentation" - UI reference and tutorials

**Question 3: Authentication**
- Header: "Auth"
- Question: "Does the app require login to access the features you want to screenshot?"
- Options:
  - "No login needed" - Public pages only
  - "Yes, I'll provide credentials" - Need to log in first

If user selects "Yes, I'll provide credentials", ask follow-up questions:
- "What is the login page URL?" (e.g., `/login`, `/sign-in`)
- "What is the email/username?"
- "What is the password?"

The script will automatically detect login form fields using Playwright's smart locators.

## Step 3: Analyze Codebase for Features

Thoroughly explore the codebase to understand the app and identify screenshot opportunities.

### 3.1: Read Documentation First

**Always start by reading these files** to understand what the app does:

1. **README.md** (and any README files in subdirectories) - Read the full README to understand:
   - What the app is and what problem it solves
   - Key features and capabilities
   - Screenshots or feature descriptions already documented

2. **CHANGELOG.md** or **HISTORY.md** - Recent features worth highlighting

3. **docs/** directory - Any additional documentation about features

### 3.2: Analyze Routes to Find Pages

Read the routing configuration to discover all available pages:

| Framework | File to Read | What to Look For |
|-----------|--------------|------------------|
| **Next.js App Router** | `app/` directory structure | Each folder with `page.tsx` is a route |
| **Next.js Pages Router** | `pages/` directory | Each file is a route |
| **Rails** | `config/routes.rb` | Read the entire file for all routes |
| **React Router** | Search for `createBrowserRouter` or `<Route` | Route definitions with paths |
| **Vue Router** | `src/router/index.js` or `router.js` | Routes array with path definitions |
| **SvelteKit** | `src/routes/` directory | Each folder with `+page.svelte` is a route |
| **Remix** | `app/routes/` directory | File-based routing |
| **Laravel** | `routes/web.php` | Route definitions |
| **Django** | `urls.py` files | URL patterns |
| **Express** | Search for `app.get`, `router.get` | Route handlers |

**Important**: Actually read these files, don't just check if they exist. The route definitions tell you what pages are available for screenshots.

### 3.3: Identify Key Components

Look for components that represent screenshottable features:

- Dashboard components
- Feature sections with distinct UI
- Forms and interactive inputs
- Data visualizations (charts, graphs, tables)
- Modals and dialogs
- Navigation and sidebars
- Settings panels
- User profile sections

### 3.4: Check for Marketing Assets

Look for existing marketing content that hints at key features:
- Landing page components (often in `components/landing/` or `components/marketing/`)
- Feature list components
- Pricing tables
- Testimonial sections

### 3.5: Build Feature List

Create a comprehensive list of discovered features with:
- Feature name (from README or component name)
- URL path (from routes)
- CSS selector to focus on (from component structure)
- Required UI state (logged in, data populated, modal open, specific tab se
