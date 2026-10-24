---
name: favicon
description: Generate favicons from a source image 
category: Development & Code Tools
source: antigravity
tags: [typescript, react, ai, workflow, design, image]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/favicon
---


Generate a complete set of favicons from the source image at `$1` and update the project's HTML with the appropriate link tags.

## When to Use
- You need to generate a complete favicon set from a single source image.
- The task includes placing the assets in the correct framework-specific static directory and updating HTML link tags.
- You want one workflow that validates the source image, detects the project type, and writes the right favicon outputs.

## Prerequisites

First, verify ImageMagick v7+ is installed by running:
```bash
which magick
```

If not found, stop and instruct the user to install it:
- **macOS**: `brew install imagemagick`
- **Linux**: `sudo apt install imagemagick`

## Step 1: Validate Source Image

1. Verify the source image exists at the provided path: `$1`
2. Check the file extension is a supported format (PNG, JPG, JPEG, SVG, WEBP, GIF)
3. If the file doesn't exist or isn't a valid image format, report the error and stop

Note whether the source is an SVG file - if so, it will also be copied as `favicon.svg`.

## Step 2: Detect Project Type and Static Assets Directory

Detect the project type and determine where static assets should be placed. Check in this order:

| Framework | Detection | Static Assets Directory |
|-----------|-----------|------------------------|
| **Rails** | `config/routes.rb` exists | `public/` |
| **Next.js** | `next.config.*` exists | `public/` |
| **Gatsby** | `gatsby-config.*` exists | `static/` |
| **SvelteKit** | `svelte.config.*` exists | `static/` |
| **Astro** | `astro.config.*` exists | `public/` |
| **Hugo** | `hugo.toml` or `config.toml` with Hugo markers | `static/` |
| **Jekyll** | `_config.yml` with Jekyll markers | Root directory (same as `index.html`) |
| **Vite** | `vite.config.*` exists | `public/` |
| **Create React App** | `package.json` has `react-scripts` dependency | `public/` |
| **Vue CLI** | `vue.config.*` exists | `public/` |
| **Angular** | `angular.json` exists | `src/assets/` |
| **Eleventy** | `.eleventy.js` or `eleventy.config.*` exists | Check `_site` output or root |
| **Static HTML** | `index.html` in root | Same directory as `index.html` |

**Important**: If existing favicon files are found (e.g., `favicon.ico`, `apple-touch-icon.png`), use their location as the target directory regardless of framework detection.

Report the detected project type and the static assets directory that will be used.

**When in doubt, ask**: If you are not 100% confident about where static assets should be placed (e.g., ambiguous project structure, multiple potential locations, unfamiliar framework), use `AskUserQuestionTool` to confirm the target directory before proceeding. It's better to ask than to put files in the wrong place.

## Step 3: Determine App Name

Find the app name from these sources (in priority order):

1. **Existing `site.webmanifest`** - Check the detected static assets directory for an existing manifest and extract the `name` field
2. **`package.json`** - Extract the `name` field if it exists
3. **Rails `config/application.rb`** - Extract the module name (e.g., `module MyApp` → "MyApp")
4. **Directory name** - Use the current working directory name as fallback

Convert the name to title case if needed (e.g., "my-app" → "My App").

## Step 4: Ensure Static Assets Directory Exists

Check if the detected static assets directory exists. If not, create it.

## Image and manifest safeguards

Inspect source dimensions/content, not only its extension. Render untrusted SVGs with resource limits and without external resource access; do not copy an unreviewed SVG into the public site. Use a reviewed square canvas/padding so aspect-preserving resize produces the declared square dimensions; inspect all outputs. Generic resized art is not automatically mask-safe: the manifest below uses `any`. Add separate `maskable` icons only after verifying their safe-zone design. Preserve existing manifest fields such as `start_url`, `scope`, `id`, shortcuts and unrelated icons, and adapt URLs to the actual deployment base. See [app icon purposes](https://developer.mozilla.org/en-US/docs/Web/Progressive_web_apps/How_to/Define_app_icons).

## Step 5: Generate Favicon Files

Run these ImageMagick commands to generate all favicon files. Replace `[STATIC_DIR]` with the detected static assets directory from Step 2.

**Important**: The `-background none` flag must come BEFORE the input file to properly preserve transparency when rendering SVGs. Placing it after the input will result in a white background.

### favicon.ico (multi-resolution: 16x16, 32x32, 48x48)
```bash
magick -background none "$1" \
  \( -clone 0 -resize 16x16 \) \
  \( -clone 0 -resize 32x32 \) \
  \( -clone 0 -resize 48x48 \) \
  -delete 0 -alpha on \
  [STATIC_DIR]/favicon.ico
```

### favicon-96x96.png
```bash
magick -background none "$1" -resize 96x96 -alpha on [STATIC_DIR]/favicon-96x96.png
```

### apple-touch-icon.png (180x180)
```bash
magick -background none "$1" -resize 180x1
