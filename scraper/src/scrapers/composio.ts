import matter from 'gray-matter';
import { fetchGitHubContents, fetchRawContent, getGitHubUrl } from '../github.js';
import type { Skill, GitHubRepo, GitHubContent } from '../types.js';

export const COMPOSIO_REPO: GitHubRepo = {
  owner: 'ComposioHQ',
  repo: 'awesome-claude-skills',
  branch: 'master',
};

// Categories mapping from the README structure
const CATEGORY_MAPPING: Record<string, string> = {
  'document-skills': 'Document Processing',
  'docx': 'Document Processing',
  'pdf': 'Document Processing',
  'pptx': 'Document Processing',
  'xlsx': 'Document Processing',
  'artifacts-builder': 'Development & Code Tools',
  'changelog-generator': 'Development & Code Tools',
  'mcp-builder': 'Development & Code Tools',
  'skill-creator': 'Development & Code Tools',
  'webapp-testing': 'Development & Code Tools',
  'connect': 'Development & Code Tools',
  'connect-apps': 'Development & Code Tools',
  'connect-apps-plugin': 'Development & Code Tools',
  'langsmith-fetch': 'Development & Code Tools',
  'brand-guidelines': 'Business & Marketing',
  'competitive-ads-extractor': 'Business & Marketing',
  'domain-name-brainstormer': 'Business & Marketing',
  'internal-comms': 'Business & Marketing',
  'lead-research-assistant': 'Business & Marketing',
  'content-research-writer': 'Communication & Writing',
  'meeting-insights-analyzer': 'Communication & Writing',
  'twitter-algorithm-optimizer': 'Communication & Writing',
  'canvas-design': 'Creative & Media',
  'image-enhancer': 'Creative & Media',
  'slack-gif-creator': 'Creative & Media',
  'theme-factory': 'Creative & Media',
  'video-downloader': 'Creative & Media',
  'file-organizer': 'Productivity & Organization',
  'invoice-organizer': 'Productivity & Organization',
  'raffle-winner-picker': 'Productivity & Organization',
  'tailored-resume-generator': 'Productivity & Organization',
  'developer-growth-analysis': 'Data & Analysis',
};

function slugify(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '');
}

function extractTags(content: string, name: string): string[] {
  const tags: string[] = [];
  const lowerContent = content.toLowerCase();

  const techKeywords = [
    'react', 'typescript', 'javascript', 'python', 'tailwind', 'css',
    'html', 'node', 'api', 'git', 'github', 'slack', 'notion', 'gmail',
    'pdf', 'docx', 'xlsx', 'markdown', 'json', 'yaml', 'cli', 'mcp',
    'playwright', 'testing', 'automation', 'ai', 'llm', 'claude'
  ];

  for (const keyword of techKeywords) {
    if (lowerContent.includes(keyword)) {
      tags.push(keyword);
    }
  }

  return [...new Set(tags)].slice(0, 10);
}

function extractUseCases(content: string): string[] {
  const useCases: string[] = [];

  // Look for "When to Use" or "Use Cases" sections
  const whenToUseMatch = content.match(/##\s*When to Use[^\n]*\n([\s\S]*?)(?=\n##|\n---|\n\*\*|$)/i);
  if (whenToUseMatch) {
    const lines = whenToUseMatch[1].split('\n').filter(l => l.trim().startsWith('-'));
    for (const line of lines) {
      const useCase = line.replace(/^-\s*/, '').trim();
      if (useCase && useCase.length > 5 && useCase.length < 200) {
        useCases.push(useCase);
      }
    }
  }

  return useCases.slice(0, 5);
}

function extractInstructions(content: string): string | undefined {
  const instructionsMatch = content.match(/##\s*Instructions[^\n]*\n([\s\S]*?)(?=\n##|\n---|\n\*\*|$)/i);
  if (instructionsMatch) {
    return instructionsMatch[1].trim().slice(0, 2000);
  }
  return undefined;
}

export async function scrapeComposioSkills(): Promise<Skill[]> {
  console.log('📦 Scraping ComposioHQ/awesome-claude-skills...');
  const skills: Skill[] = [];

  try {
    // Get root contents
    const contents = await fetchGitHubContents(COMPOSIO_REPO);

    // Filter directories that are skill folders (exclude .claude-plugin, etc.)
    const skillDirs = contents.filter(
      (item: GitHubContent) =>
        item.type === 'dir' &&
        !item.name.startsWith('.') &&
        !['template-skill', 'skill-share'].includes(item.name)
    );

    console.log(`  Found ${skillDirs.length} potential skill directories`);

    for (const dir of skillDirs) {
      try {
        // Try to get SKILL.md from the directory
        const dirContents = await fetchGitHubContents(COMPOSIO_REPO, dir.path);
        const skillFile = dirContents.find(
          (f: GitHubContent) => f.name.toLowerCase() === 'skill.md' || f.name.toLowerCase() === 'readme.md'
        );

        if (skillFile) {
          const content = await fetchRawContent(COMPOSIO_REPO, skillFile.path);
          const { data: frontmatter, content: markdownContent } = matter(content);

          const name = frontmatter.name || dir.name.split('-').map((w: string) =>
            w.charAt(0).toUpperCase() + w.slice(1)
          ).join(' ');

          const description = frontmatter.description ||
            extractFirstParagraph(markdownContent) ||
            `${name} skill for Claude`;

          const category = CATEGORY_MAPPING[dir.name] || 'Development & Code Tools';

          const skill: Skill = {
            id: `composio-${dir.name}`,
            name,
            slug: slugify(dir.name),
            description,
            category,
            source: 'composio',
            repoUrl: `https://github.com/${COMPOSIO_REPO.owner}/${COMPOSIO_REPO.repo}`,
            skillUrl: getGitHubUrl(COMPOSIO_REPO, dir.path),
            content: markdownContent.slice(0, 5000),
            tags: extractTags(content, name),
            useCases: extractUseCases(content),
            instructions: extractInstructions(content),
            scrapedAt: new Date().toISOString(),
          };

          skills.push(skill);
          console.log(`  ✓ ${name}`);
        }
      } catch (err) {
        console.log(`  ✗ Failed to process ${dir.name}: ${(err as Error).message}`);
      }
    }

    console.log(`✓ Scraped ${skills.length} skills from ComposioHQ`);
  } catch (err) {
    console.error('Failed to scrape ComposioHQ:', err);
  }

  return skills;
}

function extractFirstParagraph(content: string): string {
  // Skip headers and get first paragraph
  const lines = content.split('\n');
  let paragraph = '';

  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.startsWith('#') || trimmed === '') continue;
    if (trimmed.startsWith('-') || trimmed.startsWith('*') || trimmed.startsWith('```')) break;
    paragraph += trimmed + ' ';
    if (paragraph.length > 100) break;
  }

  return paragraph.trim().slice(0, 300);
}
