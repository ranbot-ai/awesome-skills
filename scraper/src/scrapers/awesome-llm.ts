import matter from 'gray-matter';
import type { Skill, GitHubRepo, GitHubContent } from '../types.js';
import { fetchGitHubContents, fetchRawContent, getGitHubUrl } from '../github.js';

const AWESOME_LLM_REPO: GitHubRepo = {
  owner: 'Prat011',
  repo: 'awesome-llm-skills',
  branch: 'master',
  skillsPath: '',  // Skills are at root level
};

// Directories to skip (not skills)
const SKIP_DIRS = [
  '.github',
  'template-skill',
  'document-skills',  // Contains sub-skills
];

function slugify(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
}

// Category mapping based on skill name
const CATEGORY_MAPPING: Record<string, string> = {
  // Document Processing
  'docx': 'Document Processing',
  'pdf': 'Document Processing',
  'pptx': 'Document Processing',
  'xlsx': 'Document Processing',

  // Development & Code Tools
  'artifacts-builder': 'Development & Code Tools',
  'changelog-generator': 'Development & Code Tools',
  'mcp-builder': 'Development & Code Tools',
  'skill-creator': 'Development & Code Tools',
  'webapp-testing': 'Development & Code Tools',

  // Business & Marketing
  'brand-guidelines': 'Business & Marketing',
  'competitive-ads-extractor': 'Business & Marketing',
  'domain-name-brainstormer': 'Business & Marketing',
  'internal-comms': 'Business & Marketing',
  'lead-research-assistant': 'Business & Marketing',

  // Communication & Writing
  'content-research-writer': 'Communication & Writing',
  'meeting-insights-analyzer': 'Communication & Writing',

  // Creative & Media
  'algorithmic-art': 'Creative & Media',
  'canvas-design': 'Creative & Media',
  'image-enhancer': 'Creative & Media',
  'slack-gif-creator': 'Creative & Media',
  'theme-factory': 'Creative & Media',
  'video-downloader': 'Creative & Media',

  // Productivity & Organization
  'file-organizer': 'Productivity & Organization',
  'invoice-organizer': 'Productivity & Organization',
  'raffle-winner-picker': 'Productivity & Organization',

  // Notion integrations
  'notion-knowledge-capture': 'Productivity & Organization',
  'notion-meeting-intelligence': 'Productivity & Organization',
  'notion-research-documentation': 'Productivity & Organization',
  'notion-spec-to-implementation': 'Productivity & Organization',
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
      lowerName.includes('image') || lowerName.includes('video') ||
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
      lowerName.includes('lead') || lowerName.includes('ads') ||
      lowerContent.includes('business') || lowerContent.includes('enterprise')) {
    return 'Business & Marketing';
  }

  // Communication
  if (lowerName.includes('comm') || lowerName.includes('write') ||
      lowerName.includes('meeting') || lowerContent.includes('writing')) {
    return 'Communication & Writing';
  }

  // Notion
  if (lowerName.includes('notion')) {
    return 'Productivity & Organization';
  }

  return 'AI & Agents';
}

function extractTags(content: string, name: string): string[] {
  const tags: string[] = [];
  const lowerContent = content.toLowerCase();

  const techKeywords = [
    'python', 'javascript', 'typescript', 'react', 'node',
    'pdf', 'docx', 'xlsx', 'pptx', 'markdown',
    'api', 'mcp', 'claude', 'ai', 'agent', 'llm',
    'automation', 'workflow', 'template', 'design',
    'notion', 'slack', 'youtube', 'video', 'image'
  ];

  for (const keyword of techKeywords) {
    if (lowerContent.includes(keyword)) {
      tags.push(keyword);
    }
  }

  // Add name parts as tags
  name.split('-').forEach(part => {
    if (part.length > 2 && !tags.includes(part)) {
      tags.push(part);
    }
  });

  return [...new Set(tags)].slice(0, 10);
}

function extractUseCases(content: string): string[] {
  const useCases: string[] = [];

  // Look for "When to Use" sections
  const whenMatch = content.match(/##?\s*(When to Use|Use Cases?|Examples?)[^\n]*\n([\s\S]*?)(?=\n##|\n---|\n\*\*|$)/i);

  if (whenMatch) {
    const lines = whenMatch[2].split('\n');
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

function extractDescription(content: string, frontmatterDesc?: string): string {
  if (frontmatterDesc && frontmatterDesc.length > 20) {
    return frontmatterDesc.slice(0, 300);
  }

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

  return description.slice(0, 300) || 'LLM skill for AI agents';
}

export async function scrapeAwesomeLLMSkills(): Promise<Skill[]> {
  console.log('🎯 Scraping Prat011/awesome-llm-skills...');
  const skills: Skill[] = [];

  try {
    // Get root directory contents
    const contents = await fetchGitHubContents(AWESOME_LLM_REPO, '');

    // Filter directories that are skills (exclude README, CONTRIBUTING, etc.)
    const skillDirs = contents.filter(
      (item: GitHubContent) =>
        item.type === 'dir' &&
        !item.name.startsWith('.') &&
        !SKIP_DIRS.includes(item.name)
    );

    console.log(`  Found ${skillDirs.length} skill directories`);

    for (const dir of skillDirs) {
      try {
        // Look for SKILL.md or README.md in each directory
        const dirContents = await fetchGitHubContents(AWESOME_LLM_REPO, dir.path);
        const skillFile = dirContents.find(
          (f: GitHubContent) => f.name.toLowerCase() === 'skill.md' || f.name.toLowerCase() === 'readme.md'
        );

        if (skillFile) {
          const content = await fetchRawContent(AWESOME_LLM_REPO, skillFile.path);
          const { data: frontmatter, content: markdownContent } = matter(content);

          const name = frontmatter.name || dir.name.split('-').map((w: string) =>
            w.charAt(0).toUpperCase() + w.slice(1)
          ).join(' ');

          const description = extractDescription(markdownContent, frontmatter.description);
          const category = inferCategory(dir.name, content);

          const skill: Skill = {
            id: `awesome-llm-${dir.name}`,
            name,
            slug: `awesome-llm-${slugify(dir.name)}`,
            description,
            category,
            source: 'awesome-llm',
            repoUrl: `https://github.com/${AWESOME_LLM_REPO.owner}/${AWESOME_LLM_REPO.repo}`,
            skillUrl: getGitHubUrl(AWESOME_LLM_REPO, dir.path),
            content: markdownContent.slice(0, 5000),
            tags: extractTags(content, dir.name),
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

    console.log(`✓ Scraped ${skills.length} skills from Awesome LLM Skills`);
  } catch (err) {
    console.error('Failed to scrape Awesome LLM Skills:', err);
  }

  return skills;
}

export { AWESOME_LLM_REPO };
