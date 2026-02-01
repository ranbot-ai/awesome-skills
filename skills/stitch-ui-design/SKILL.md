---
name: stitch-ui-design
description: Expert guide for creating effective prompts for Google Stitch AI UI design tool. Use when user wants to design UI/UX in Stitch, create app interfaces, generate mobile/web designs, or needs help crafti
category: Creative & Media
source: antigravity
tags: [react, api, ai, workflow, template, design, image, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/stitch-ui-design
---


# Stitch UI Design Prompting

Expert guidance for crafting effective prompts in Google Stitch, the AI-powered UI design tool by Google Labs. This skill helps create precise, actionable prompts that generate high-quality UI designs for web and mobile applications.

## What is Google Stitch?

Google Stitch is an experimental AI UI generator powered by Gemini 2.5 Flash that transforms text prompts and visual references into functional UI designs. It supports:

- Text-to-UI generation from natural language prompts
- Image-to-UI conversion from sketches, wireframes, or screenshots
- Multi-screen app flows and responsive layouts
- Export to HTML/CSS, Figma, and code
- Iterative refinement with variants and annotations

## Core Prompting Principles

### 1. Be Specific and Detailed

Generic prompts yield generic results. Specific prompts with clear requirements produce tailored, professional designs.

**Poor prompt:**
```
Create a dashboard
```

**Effective prompt:**
```
Member dashboard with course modules grid, progress tracking bar, 
and community feed sidebar using purple theme and card-based layout
```

**Why it works:** Specifies components (modules, progress, feed), layout structure (grid, sidebar), visual style (purple theme, cards), and context (member dashboard).

### 2. Define Visual Style and Theme

Always include color schemes, design aesthetics, and visual direction to avoid generic AI outputs.

**Components to specify:**
- Color palette (primary colors, accent colors)
- Design style (minimalist, modern, playful, professional, glassmorphic)
- Typography preferences (if any)
- Spacing and density (compact, spacious, balanced)

**Example:**
```
E-commerce product page with hero image gallery, add-to-cart CTA, 
reviews section, and related products carousel. Use clean minimalist 
design with sage green accents and generous white space.
```

### 3. Structure Multi-Screen Flows Clearly

For apps with multiple screens, list each screen as bullet points before generation.

**Approach:**
```
Fitness tracking app with:
- Onboarding screen with goal selection
- Home dashboard with daily stats and activity rings
- Workout library with category filters
- Profile screen with achievements and settings
```

Stitch will ask for confirmation before generating multiple screens, ensuring alignment with your vision.

### 4. Specify Platform and Responsive Behavior

Indicate whether the design is for mobile, tablet, desktop, or responsive web.

**Examples:**
```
Mobile app login screen (iOS style) with email/password fields and social auth buttons

Responsive landing page that adapts from mobile (320px) to desktop (1440px) 
with collapsible navigation
```

### 5. Include Functional Requirements

Describe interactive elements, states, and user flows to generate more complete designs.

**Elements to specify:**
- Button actions and CTAs
- Form fields and validation
- Navigation patterns
- Loading states
- Empty states
- Error handling

**Example:**
```
Checkout flow with:
- Cart summary with quantity adjusters
- Shipping address form with validation
- Payment method selection (cards, PayPal, Apple Pay)
- Order confirmation with tracking number
```

## Prompt Structure Template

Use this template for comprehensive prompts:

```
[Screen/Component Type] for [User/Context]

Key Features:
- [Feature 1 with specific details]
- [Feature 2 with specific details]
- [Feature 3 with specific details]

Visual Style:
- [Color scheme]
- [Design aesthetic]
- [Layout approach]

Platform: [Mobile/Web/Responsive]
```

**Example:**
```
Dashboard for SaaS analytics platform

Key Features:
- Top metrics cards showing MRR, active users, churn rate
- Line chart for revenue trends (last 30 days)
- Recent activity feed with user actions
- Quick action buttons for reports and exports

Visual Style:
- Dark mode with blue/purple gradient accents
- Modern glassmorphic cards with subtle shadows
- Clean data visualization with accessible colors

Platform: Responsive web (desktop-first)
```

## Iteration Strategies

### Refine with Annotations

Use Stitch's "annotate to edit" feature to make targeted changes without rewriting the entire prompt.

**Workflow:**
1. Generate initial design from prompt
2. Annotate specific elements that need changes
3. Describe modifications in natural language
4. Stitch updates only the annotated areas

**Example annotations:**
- "Make this button larger and use primary color"
- "Add more spacing between these cards"
- "Change this to a horizontal layout"

### Generate Variants

Request multiple variations to explore different design directions:

```
Generate 3 variants of this hero section:
1. Image-focused with minimal text
2. Text-heavy with supporting graphics
3. Video background with overlay content
```

### Progressive Refinement

Start broad, then add specificity in follow-up prompts:

**Initial:**
```
E-commerce homepage
```

**Refinement 1:**
```
Add featured products section with 4-column grid and hover effects
```
