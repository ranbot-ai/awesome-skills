import matter from 'gray-matter';
import type { Skill, GitHubRepo, GitHubContent } from '../types.js';
import { fetchGitHubContents, fetchRawContent, getGitHubUrl } from '../github.js';

const SUPERPOWERS_REPO: GitHubRepo = {
  owner: 'obra',
  repo: 'superpowers',
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
  'test-driven-development': 'Development & Code Tools',
  'systematic-debugging': 'Development & Code Tools',
  'verification-before-completion': 'Development & Code Tools',
  'brainstorming': 'Collaboration & Project Management',
  'writing-plans': 'Collaboration & Project Management',
  'executing-plans': 'Collaboration & Project Management',
  'dispatching-parallel-agents': 'AI & Agents',
  'requesting-code-review': 'Collaboration & Project Management',
  'receiving-code-review': 'Collaboration & Project Management',
  'using-git-worktrees': 'Development & Code Tools',
  'finishing-a-development-branch': 'Development & Code Tools',
  'subagent-driven-development': 'AI & Agents',
  'writing-skills': 'AI & Agents',
  'using-superpowers': 'AI & Agents',
};

function inferCategory(name: string, content: string): string {
  // Check direct mapping first
  if (CATEGORY_MAPPING[name]) {
    return CATEGORY_MAPPING[name];
  }

  const lowerName = name.toLowerCase();
  const lowerContent = content.toLowerCase();

  // Testing & Development
  if (lowerName.includes('test') || lowerName.includes('debug') ||
      lowerName.includes('code') || lowerName.includes('dev') ||
      lowerContent.includes('tdd') || lowerContent.includes('testing')) {
    return 'Development & Code Tools';
  }

  // Collaboration
  if (lowerName.includes('review') || lowerName.includes('plan') ||
      lowerName.includes('brainstorm') || lowerContent.includes('collaboration')) {
    return 'Collaboration & Project Management';
  }

  // Git operations
  if (lowerName.includes('git') || lowerName.includes('branch') ||
      lowerContent.includes('git') || lowerContent.includes('commit')) {
    return 'Development & Code Tools';
  }

  // AI & Agents
  if (lowerName.includes('agent') || lowerName.includes('subagent') ||
      lowerContent.includes('agent') || lowerContent.includes('autonomous')) {
    return 'AI & Agents';
  }

  return 'AI & Agents';
}

function extractTags(content: string, name: string): string[] {
  const tags: string[] = [];
  const lowerContent = content.toLowerCase();

  const techKeywords = [
    'tdd', 'testing', 'debug', 'debugging', 'git', 'worktree',
    'code-review', 'planning', 'brainstorming', 'subagent',
    'workflow', 'automation', 'agent', 'verification',
    'red-green-refactor', 'systematic', 'methodology'
  ];

  for (const keyword of techKeywords) {
    if (lowerContent.includes(keyword)) {
      tags.push(keyword);
    }
  }

  // Add skill name parts as tags
  name.split('-').forEach(part => {
    if (part.length > 2) {
      tags.push(part);
    }
  });

  return [...new Set(tags)].slice(0, 10);
}

function extractUseCases(content: string): string[] {
  const useCases: string[] = [];

  // Look for when to use sections
  const whenMatch = content.match(/##?\s*(When to Use|Use when|Activates)[^\n]*\n([\s\S]*?)(?=\n##|\n---|\n\*\*|$)/i);

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

  return description.slice(0, 300) || 'Superpowers skill for AI agents';
}

export async function scrapeSuperPowersSkills(): Promise<Skill[]> {
  console.log('⚡ Scraping obra/superpowers...');
  const skills: Skill[] = [];

  try {
    // Get skills directory contents
    const contents = await fetchGitHubContents(SUPERPOWERS_REPO, SUPERPOWERS_REPO.skillsPath!);

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
        const dirContents = await fetchGitHubContents(SUPERPOWERS_REPO, dir.path);
        const skillFile = dirContents.find(
          (f: GitHubContent) => f.name.toLowerCase() === 'skill.md' || f.name.toLowerCase() === 'readme.md'
        );

        if (skillFile) {
          const content = await fetchRawContent(SUPERPOWERS_REPO, skillFile.path);
          const { data: frontmatter, content: markdownContent } = matter(content);

          const name = frontmatter.name || dir.name.split('-').map((w: string) =>
            w.charAt(0).toUpperCase() + w.slice(1)
          ).join(' ');

          const description = extractDescription(markdownContent, frontmatter.description);
          const category = inferCategory(dir.name, content);

          const skill: Skill = {
            id: `superpowers-${dir.name}`,
            name,
            slug: `superpowers-${slugify(dir.name)}`,
            description,
            category,
            source: 'superpowers',
            repoUrl: `https://github.com/${SUPERPOWERS_REPO.owner}/${SUPERPOWERS_REPO.repo}`,
            skillUrl: getGitHubUrl(SUPERPOWERS_REPO, dir.path),
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

    console.log(`✓ Scraped ${skills.length} skills from Superpowers`);
  } catch (err) {
    console.error('Failed to scrape Superpowers:', err);
  }

  return skills;
}

export { SUPERPOWERS_REPO };
