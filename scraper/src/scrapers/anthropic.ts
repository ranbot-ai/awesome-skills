import matter from 'gray-matter';
import type { Skill, GitHubRepo, GitHubContent } from '../types.js';
import { fetchGitHubContents, fetchRawContent, getGitHubUrl } from '../github.js';

const ANTHROPIC_REPO: GitHubRepo = {
  owner: 'anthropics',
  repo: 'skills',
  branch: 'main',
  skillsPath: 'skills',
};

function slugify(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
}

// Category mapping based on skill content and name
const CATEGORY_MAPPING: Record<string, string> = {
  'docx': 'Document Processing',
  'pdf': 'Document Processing',
  'pptx': 'Document Processing',
  'xlsx': 'Document Processing',
  'canvas-design': 'Creative & Media',
  'image-enhancer': 'Creative & Media',
  'music-creation': 'Creative & Media',
  'brand-guidelines': 'Business & Marketing',
  'internal-comms': 'Communication & Writing',
  'content-research-writer': 'Communication & Writing',
  'mcp-builder': 'Development & Code Tools',
  'webapp-testing': 'Development & Code Tools',
  'artifacts-builder': 'Development & Code Tools',
};

function inferCategory(name: string, content: string): string {
  // Check direct mapping first
  if (CATEGORY_MAPPING[name]) {
    return CATEGORY_MAPPING[name];
  }

  const lowerName = name.toLowerCase();
  const lowerContent = content.toLowerCase();

  // Document processing
  if (lowerName.includes('doc') || lowerName.includes('pdf') ||
      lowerName.includes('ppt') || lowerName.includes('xlsx') ||
      lowerContent.includes('document') || lowerContent.includes('spreadsheet')) {
    return 'Document Processing';
  }

  // Creative
  if (lowerName.includes('design') || lowerName.includes('art') ||
      lowerName.includes('music') || lowerName.includes('image') ||
      lowerContent.includes('creative') || lowerContent.includes('visual')) {
    return 'Creative & Media';
  }

  // Development
  if (lowerName.includes('code') || lowerName.includes('dev') ||
      lowerName.includes('test') || lowerName.includes('mcp') ||
      lowerContent.includes('developer') || lowerContent.includes('programming')) {
    return 'Development & Code Tools';
  }

  // Business
  if (lowerName.includes('brand') || lowerName.includes('market') ||
      lowerContent.includes('business') || lowerContent.includes('enterprise')) {
    return 'Business & Marketing';
  }

  // Communication
  if (lowerName.includes('comm') || lowerName.includes('write') ||
      lowerContent.includes('writing') || lowerContent.includes('content')) {
    return 'Communication & Writing';
  }

  return 'AI & Agents';
}

function extractTags(content: string, name: string): string[] {
  const tags: string[] = [];
  const lowerContent = content.toLowerCase();

  const techKeywords = [
    'python', 'javascript', 'typescript', 'react', 'node',
    'pdf', 'docx', 'xlsx', 'pptx', 'markdown',
    'api', 'mcp', 'claude', 'ai', 'agent',
    'automation', 'workflow', 'template', 'design',
    'document', 'spreadsheet', 'presentation', 'image'
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

  // Look for "Examples" or "Use Cases" sections
  const examplesMatch = content.match(/##?\s*(Examples?|Use Cases?|When to Use)[^\n]*\n([\s\S]*?)(?=\n##|\n---|\n\*\*|$)/i);

  if (examplesMatch) {
    const lines = examplesMatch[2].split('\n');
    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed.startsWith('-') || trimmed.startsWith('*')) {
        const useCase = trimmed.replace(/^[-*]\s*/, '').trim();
        if (useCase.length > 10 && useCase.length < 200) {
          useCases.push(useCase);
        }
      }
    }
  }

  return useCases.slice(0, 5);
}

function extractDescription(content: string): string {
  const lines = content.split('\n');
  let description = '';
  let foundHeader = false;

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    // Skip headers
    if (trimmed.startsWith('#')) {
      foundHeader = true;
      continue;
    }

    // Skip code blocks and lists at the start
    if (trimmed.startsWith('```') || trimmed.startsWith('-') || trimmed.startsWith('*')) continue;

    // Get the first paragraph after any header
    if (foundHeader || description === '') {
      description += (description ? ' ' : '') + trimmed;
      if (description.length > 100) break;
    }
  }

  return description.slice(0, 300) || 'Anthropic skill for Claude';
}

export async function scrapeAnthropicSkills(): Promise<Skill[]> {
  console.log('🔮 Scraping anthropics/skills...');
  const skills: Skill[] = [];

  try {
    // Get skills directory contents
    const contents = await fetchGitHubContents(ANTHROPIC_REPO, ANTHROPIC_REPO.skillsPath!);

    // Filter directories (skills are in subdirectories)
    const skillDirs = contents.filter(
      (item: GitHubContent) =>
        item.type === 'dir' &&
        !item.name.startsWith('.')
    );

    console.log(`  Found ${skillDirs.length} skill directories`);

    for (const dir of skillDirs) {
      try {
        // Look for SKILL.md in each directory
        const dirContents = await fetchGitHubContents(ANTHROPIC_REPO, dir.path);
        const skillFile = dirContents.find(
          (f: GitHubContent) => f.name.toLowerCase() === 'skill.md' || f.name.toLowerCase() === 'readme.md'
        );

        if (skillFile) {
          const content = await fetchRawContent(ANTHROPIC_REPO, skillFile.path);
          const { data: frontmatter, content: markdownContent } = matter(content);

          const name = frontmatter.name || dir.name.split('-').map((w: string) =>
            w.charAt(0).toUpperCase() + w.slice(1)
          ).join(' ');

          const description = frontmatter.description ||
            extractDescription(markdownContent) ||
            `${name} skill for Claude`;

          const category = inferCategory(dir.name, content);

          const skill: Skill = {
            id: `anthropic-${dir.name}`,
            name,
            slug: slugify(dir.name),
            description,
            category,
            source: 'anthropic',
            repoUrl: `https://github.com/${ANTHROPIC_REPO.owner}/${ANTHROPIC_REPO.repo}`,
            skillUrl: getGitHubUrl(ANTHROPIC_REPO, dir.path),
            content: markdownContent.slice(0, 5000),
            tags: extractTags(content, name),
            useCases: extractUseCases(content),
            scrapedAt: new Date().toISOString(),
          };

          skills.push(skill);
          console.log(`  ✓ ${name}`);
        }
      } catch (err) {
        console.log(`  ✗ Failed to process ${dir.name}: ${(err as Error).message}`);
      }
    }

    console.log(`✓ Scraped ${skills.length} skills from Anthropic`);
  } catch (err) {
    console.error('Failed to scrape Anthropic:', err);
  }

  return skills;
}

export { ANTHROPIC_REPO };
