---
name: hugo-to-markdown
description: Convert Hugo documentation sites and Hugo-managed content into standard Markdown. 
category: Document Processing
source: antigravity
tags: [python, markdown, ai, agent, workflow, template, document, presentation, image, security]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/hugo-to-markdown
---


# Hugo To Markdown
## When to Use

Use this skill when you need convert Hugo documentation sites and Hugo-managed content into standard Markdown. Use when Agent needs to inspect a local Hugo repository, read hugo.toml or config files, content/, archetypes/, layouts/_shortcodes/, layouts/_markup/, and related docs content, then produce Markdown...


## Overview

Use this skill when Markdown output must be derived from the local Hugo site, not guessed from generic Hugo knowledge. The conversion rules are the combination of Hugo's official behavior and the repository's own configuration, shortcode templates, render hooks, archetypes, and content conventions.

The target output is standard Markdown:

- Keep plain Markdown and YAML front matter.
- Replace or materialize Hugo-only constructs.
- Preserve meaning when exact rendering is not safely reproducible.
- Prefer explicit Markdown text over live Hugo template syntax.
- Distinguish literal Hugo syntax examples from active Hugo features before rewriting anything.

## Official Basis

Treat the repository's own Hugo configuration and templates as the primary ruleset. For any site under conversion, inspect these rule sources in the user's provided site root:

- `hugo.toml` (or `hugo.yaml`, `hugo.yml`, `hugo.json`, or `config/*`)
- `archetypes/*`
- `data/*`
- `layouts/_shortcodes/*` or `layouts/shortcodes/*`
- `layouts/_markup/*`
- `content/**`

Also read any local docs that define shortcode, front matter, bundle, resource, and render-hook behavior.

Do not assume built-in Hugo defaults if the repository overrides them locally.

## Workflow

### 1. Inventory the site before converting files

Always inspect the site-level rules first.

```bash
python3 scripts/inventory_hugo_rules.py --site-root /path/to/hugo-site
```

Example invocation for the user's site:

```bash
python3 skills/hugo-to-markdown/scripts/inventory_hugo_rules.py \
  --site-root /path/to/your-hugo-site
```

This inventory step is mandatory for batch work. It identifies:

- active config files
- module mounts and content roots
- custom shortcodes
- custom render hooks
- front matter keys seen in content
- shortcode usage across content files

### 2. Convert with repository rules, not generic heuristics

Read `references/conversion-workflow.md` before changing files. Then:

1. Resolve the real content root from `hugo.toml`, `config.*`, and module mounts.
2. Read archetypes to understand expected front matter shape.
3. Read the front matter configuration to understand date aliases, fallback order, filename-derived dates, and other inferred metadata.
4. Read site data sources in `data/` when shortcodes or partials pull structured content from them.
5. Read custom shortcode templates in `layouts/_shortcodes/` or `layouts/shortcodes/`.
6. Classify each encountered shortcode as embedded, custom, or inline, then check whether it uses named or positional arguments, block syntax, or self-closing syntax.
7. Read render hooks in `layouts/_markup/`.
8. Check whether the repo already defines Markdown- or JSON-facing export templates and partials; if it does, use those as evidence for how the site itself downgrades Hugo constructs.
9. Follow `include`-style shortcodes into referenced content files when the docs site composes content from shared fragments.
10. Convert one file or one coherent section at a time.

### 3. Preserve semantics during conversion

Use these rules by default:

- Keep YAML front matter unless the user explicitly asks for front-matter-free Markdown.
- Preserve core fields such as `title`, `description`, `date`, `draft`, `aliases`, `slug`, `url`, `weight`, and nested `params` when they still carry meaning.
- Preserve `publishDate`, `lastmod`, `expiryDate`, and page resource metadata when they still affect meaning or downstream routing.
- Normalize reserved Hugo front matter keys to their canonical names when the repo mixes casing, for example `Title` to `title`, `Description` to `description`, and `LinkTitle` to `linkTitle`.
- Account for Hugo front matter aliases and tokens before deciding a field is unused. The official Hugo docs recognize aliases such as `pubdate`, `published`, `modified`, and `unpublishdate`, plus tokens such as `:default`, `:filename`, `:fileModTime`, and `:git`.
- Convert Hugo internal links to normal Markdown links with resolved destinations.
- Replace Hugo shortcodes with plain Markdown, HTML, or explicit notes only after reading the local shortcode implementation.
- Preserve or materialize shortcode arguments according to the shortcode's real calling convention. Do not assume every shortcode is named-argument, self-closing, or block-capable.
- Materialize dynamically generated lists and tables when the shortcode renders content from sections or data files.
- Leave literal Hugo examples unchanged when the document is documenting Hugo syntax rather than invoking it. This applies both inside fenced code blocks and to escaped forms such as `{{</* foo */>}}` or `{{%/* foo
