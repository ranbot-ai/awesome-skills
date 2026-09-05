---
name: content-creator
description: Draft and review audience-specific content using supplied brand examples, local text diagnostics, and adaptable channel templates. 
category: Document Processing
source: antigravity
tags: [python, markdown, ai, workflow, template, design, document, image, rag, seo]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/content-creator
---


# Content Creator

Draft and review audience-specific content using supplied brand examples, local text diagnostics, and adaptable channel templates.

## When to Use
Use this skill when writing blog posts, creating social media content, establishing brand voice, optimizing content for SEO, or planning content calendars.

## Keywords
content creation, blog posts, SEO, brand voice, social media, content calendar, marketing content, content strategy, content marketing, brand consistency, content optimization, social media marketing, content planning, blog writing, content frameworks, brand guidelines, social media strategy

## Inputs and boundaries

Obtain the audience, purpose, approved claims and sources, brand examples, channel,
and desired next action. Reuse supplied constraints; do not invent audience research.
Python 3 is sufficient for the optional local scripts. Run the examples from this
skill directory with a permitted UTF-8 input below the working directory (maximum
1 MiB); paths elsewhere are rejected. The scripts read that file and print diagnostics,
without calling an analytics service or editing it. Review any private text before
sharing the output. Drafting does not authorize scheduling, sending or publication.

## Quick Start

### For Brand Voice Development
1. Run `scripts/brand_voice_analyzer.py` on existing content to record rough lexical features
2. Review `references/brand_guidelines.md` to select voice attributes
3. Apply chosen voice consistently across all content

### For Blog Content Creation
1. Choose template from `references/content_frameworks.md`
2. Research keywords for topic
3. Write content following template structure
4. Run `scripts/seo_optimizer.py [file] [primary-keyword]` to optimize
5. Review suggestions against the audience and actual page before publishing

### For Social Media Content
1. Review platform best practices in `references/social_media_optimization.md`
2. Use appropriate template from `references/content_frameworks.md`
3. Optimize based on platform-specific guidelines
4. Schedule using `assets/content_calendar_template.md`

## Core Workflows

### Establishing Brand Voice (First Time Setup)

When creating content for a new brand or client:

1. **Analyze Existing Content** (if available)
   ```bash
   python scripts/brand_voice_analyzer.py existing_content.txt
   ```
   
2. **Define Voice Attributes**
   - Review brand personality archetypes in `references/brand_guidelines.md`
   - Select primary and secondary archetypes
   - Choose 3-5 tone attributes
   - Document in brand guidelines

3. **Create Voice Sample**
   - Write 3 sample pieces in chosen voice
   - Compare samples manually with approved examples; use the analyzer only for lexical clues
   - Refine based on results

### Creating SEO-Optimized Blog Posts

1. **Keyword Research**
   - Identify the reader question and relevant search intent from actual research
   - Record related questions that the piece needs to answer
   - Do not invent search volumes or treat word frequency as semantic research

2. **Content Structure**
   - Use blog template from `references/content_frameworks.md`
   - Use a descriptive title and headings; use the reader's terminology naturally
   - Use enough detail to answer the question; there is no universal SEO word count

3. **Optimization Check**
   ```bash
   python scripts/seo_optimizer.py blog_post.md "primary keyword" "secondary,keywords,list"
   ```

4. **Apply SEO Recommendations**
   - Remove repetition that hurts clarity; do not target a keyword-density percentage
   - Ensure proper heading structure
   - Add internal and external links
   - Optimize meta description

### Social Media Content Creation

1. **Platform Selection**
   - Identify primary platforms based on audience
   - Review platform-specific guidelines in `references/social_media_optimization.md`

2. **Content Adaptation**
   - Start with blog post or core message
   - Use repurposing matrix from `references/content_frameworks.md`
   - Adapt for each platform following templates

3. **Optimization Checklist**
   - Platform-appropriate length
   - Audience-informed posting time to test
   - Correct image dimensions
   - Platform-specific hashtags
   - Engagement elements (polls, questions)

### Content Calendar Planning

1. **Monthly Planning**
   - Copy `assets/content_calendar_template.md`
   - Set monthly goals and KPIs
   - Identify key campaigns/themes

2. **Weekly Distribution**
   - Choose a mix based on goals, production capacity and observed audience needs
   - Balance platforms throughout week
   - Label untested timing assumptions and compare results over a stated period

3. **Batch Creation**
   - Create all weekly content in one session
   - Maintain consistent voice across pieces
   - Prepare all visual assets together

## Key Scripts

### brand_voice_analyzer.py
Counts a small English vocabulary and estimates sentence length/readability. It cannot establish authentic brand voice or vali
