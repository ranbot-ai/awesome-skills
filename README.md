# Agent Skills Collection

> A curated collection of AI agent skills scraped from GitHub repositories, displayed on a beautiful, modern website.
>
> **Built by [RanBOT Labs](https://ranbot.online)**

## Features

- **Multi-Source Scraper**: Collects agent skills from 5+ GitHub repositories
- **Modern Website**: Next.js 16 + Tailwind CSS frontend with search, filtering, and detailed skill pages
- **70+ Skills**: Curated from top AI agent skill repositories
- **Categories**: Skills organized by category (Development, AI & Agents, Business, Creative, etc.)
- **Search & Filter**: Find skills by name, description, tags, or category
- **Automated Updates**: GitHub Actions workflow for scheduled scraping

## Data Sources

| Repository | Stars | Description |
|------------|-------|-------------|
| [obra/superpowers](https://github.com/obra/superpowers) | 35k+ | Agentic skills framework & development methodology |
| [anthropics/skills](https://github.com/anthropics/skills) | 52k+ | Official Anthropic Claude skills |
| [ComposioHQ/awesome-claude-skills](https://github.com/ComposioHQ/awesome-claude-skills) | 25k+ | Community Claude AI skills |
| [OpenHands/OpenHands](https://github.com/OpenHands/OpenHands) | 67k+ | AI-driven development skills |
| [Prat011/awesome-llm-skills](https://github.com/Prat011/awesome-llm-skills) | 700+ | LLM and AI Agent skills collection |

## Install Skills Locally

Install skills directly to `~/.claude/skills` for use with Claude Code or other AI agents.

### One-liner Installation

```bash
# Install all skills
curl -fsSL https://raw.githubusercontent.com/ranbot-ai/awesome-skills/main/scripts/install-skills.sh | bash

# Install specific skills
curl -fsSL https://raw.githubusercontent.com/ranbot-ai/awesome-skills/main/scripts/install-skills.sh | bash -s -- code-review docker kubernetes
```

### Using the Install Script

```bash
# Clone the repo first
git clone https://github.com/ranbot-ai/awesome-skills.git
cd awesome-skills

# List available skills
./scripts/install-skills.sh --list

# Install all skills
./scripts/install-skills.sh

# Install specific skills
./scripts/install-skills.sh code-review docker kubernetes

# Install from local data (after scraping)
./scripts/install-skills.sh --local ./data

# Search for skills
./scripts/install-skills.sh --search docker

# Install all skills from a source (anthropic, composio, superpowers, openhands)
./scripts/install-skills.sh --source anthropic

# Install skills by category
./scripts/install-skills.sh --category "Development"

# Show skill info
./scripts/install-skills.sh --info code-review

# Update existing skills
./scripts/install-skills.sh --update

# Uninstall a skill
./scripts/install-skills.sh --uninstall code-review

# Remove all installed skills
./scripts/install-skills.sh --clean
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `CLAUDE_SKILLS_DIR` | Override skills directory (default: `~/.claude/skills`) |

---

## Quick Start (Development)

### 1. Install Dependencies

```bash
npm run setup
```

### 2. Run the Scraper

```bash
# Just scrape
npm run scrape

# Build scraper first, then scrape
npm run scrape:build
```

This will fetch the latest skills from GitHub and save them to the `data/` directory.

**Note**: For higher rate limits (5000 req/hour vs 60), set a GitHub token:

```bash
export GITHUB_TOKEN=your_github_token
npm run scrape
```

### 3. Start the Development Server

```bash
npm run dev
```

Visit [http://localhost:3000](http://localhost:3000) to see the website.

### 4. Build for Production

```bash
npm run build
npm run start
```

## Scripts

| Command | Description |
|---------|-------------|
| `npm run setup` | Install all dependencies |
| `npm run scrape` | Run the scraper to fetch skills |
| `npm run scrape:build` | Build and run the scraper |
| `npm run update-skills` | Scrape and copy data to web |
| `npm run dev` | Start development server |
| `npm run build` | Build for production |
| `npm run start` | Start production server |
| `npm run deploy` | Scrape, copy data, commit & push |
| `npm run deploy:build` | Full deploy with web build |

## Automated Scraping

### Using the Shell Script

```bash
# Just scrape and update data
./scripts/scrape-and-deploy.sh

# Scrape and push to remote
./scripts/scrape-and-deploy.sh --push

# Scrape, push, and build web app
./scripts/scrape-and-deploy.sh --push --build
```

### Using GitHub Actions

The project includes a GitHub Actions workflow that runs daily at 6 AM UTC:

- **Automatic**: Scheduled daily scraping
- **Manual**: Trigger from GitHub Actions tab
- **Commits**: Automatically commits and pushes updates

See `.github/workflows/scrape-skills.yml` for configuration.

## Project Structure

```
awesome-skills/
├── scraper/                # Node.js skill scraper
│   ├── src/
│   │   ├── index.ts        # Main entry point
│   │   ├── types.ts        # TypeScript types
│   │   ├── github.ts       # GitHub API utilities
│   │   ├── processor.ts    # Data processing
│   │   └── scrapers/       # Source-specific scrapers
│   │       ├── anthropic.ts
│   │       ├── composio.ts
│   │       ├── openhands.ts
│   │       ├── superpowers.ts
│   │       └── awesome-llm.ts
│   └── package.json
├── web/                    # Next.js frontend
│   ├── src/
│   │   ├── app/            # Next.js app router
│   │   │   ├── page.tsx    # Homepage
│   │   │   ├── about/      # About page
│   │   │   └── skill/      # Skill detail pages
│   │   ├── components/     # React components
│   │   ├── lib/            # Utility functions
│   │   └── types/          # TypeScript types
│   └── package.json
├── scripts/                # Automation scripts
│   ├── scrape-and-deploy.sh  # Scrape and deploy to repo
│   ├── build-static.sh       # Build static site
│   └── install-skills.sh     # Install skills locally
├── .github/
│   └── workflows/
│       └── scrape-skills.yml
├── data/                   # Scraped skill data
│   ├── skills.json         # All skills data
│   ├── search-index.json   # Search index
│   └── skills/             # Individual skill files
└── package.json            # Root package.json
```

## Website Features

### Homepage
- Hero section with animated gradient
- Source cards with GitHub stars
- Search bar with instant filtering
- Category cards for browsing by category
- Skills grid with hover effects
- Filter by category and source

### About Page
- Agent Skills specification overview
- Compatible tools list
- Links to official documentation

### Skill Detail Page
- Full documentation display
- Tags and metadata
- Use cases (when available)
- Related skills
- Quick links to GitHub
- Scraped date tracking

## Technologies

### Scraper
- **TypeScript** - Type-safe JavaScript
- **gray-matter** - Parse YAML frontmatter
- **GitHub API** - Fetch repository contents

### Website
- **Next.js 16** - React framework with App Router
- **Tailwind CSS** - Utility-first CSS
- **Lucide React** - Beautiful icons
- **TypeScript** - Type safety

## Adding New Sources

To add a new skill source:

1. Create a scraper in `scraper/src/scrapers/`:

```typescript
import type { Skill, GitHubRepo } from '../types.js';

export const NEW_REPO: GitHubRepo = {
  owner: 'owner',
  repo: 'repo',
  branch: 'main',
  skillsPath: 'skills',
};

export async function scrapeNewSource(): Promise<Skill[]> {
  // Implementation
}
```

2. Add the source type to `scraper/src/types.ts`

3. Update `scraper/src/processor.ts` to include the new source

4. Import and call the scraper in `scraper/src/index.ts`

5. Update `web/src/lib/skills.ts` with source label and color

6. Update `web/src/components/Footer.tsx` with source link

## Environment Variables

| Variable | Description |
|----------|-------------|
| `GITHUB_TOKEN` | GitHub token for higher API rate limits |
| `GH_TOKEN` | Alternative GitHub token variable |

## License

MIT

---

**[RanBOT Labs](https://ranbot.online)** - Building intelligent tools for the AI era.
