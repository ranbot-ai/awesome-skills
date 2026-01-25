import matter from 'gray-matter';
import { fetchGitHubContents, fetchRawContent, getGitHubFileUrl } from '../github.js';
import type { Skill, GitHubRepo, GitHubContent } from '../types.js';

export const OPENHANDS_REPO: GitHubRepo = {
  owner: 'OpenHands',
  repo: 'OpenHands',
  branch: 'main',
  skillsPath: 'skills',
};

function slugify(name: string): string {
  return name
    .toLowerCase()
    .replace(/\.md$/, '')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '');
}

function inferCategory(name: string, content: string): string {
  const lowerName = name.toLowerCase();
  const lowerContent = content.toLowerCase();

  if (lowerName.includes('git') || lowerName.includes('pr') || lowerName.includes('review') ||
      lowerContent.includes('pull request') || lowerContent.includes('code review')) {
    return 'Development & Code Tools';
  }
  if (lowerName.includes('docker') || lowerName.includes('azure') || lowerName.includes('bitbucket')) {
    return 'Development & Code Tools';
  }
  if (lowerName.includes('agent') || lowerName.includes('memory')) {
    return 'AI & Agents';
  }
  if (lowerName.includes('test') || lowerName.includes('fix')) {
    return 'Development & Code Tools';
  }
  if (lowerName.includes('tool')) {
    return 'Productivity & Organization';
  }

  return 'Development & Code Tools';
}

function extractTags(content: string, name: string): string[] {
  const tags: string[] = [];
  const lowerContent = content.toLowerCase();

  const techKeywords = [
    'git', 'github', 'gitlab', 'bitbucket', 'azure', 'docker', 'kubernetes',
    'python', 'typescript', 'javascript', 'bash', 'shell', 'linux',
    'testing', 'ci/cd', 'automation', 'pr', 'code review', 'agent',
    'memory', 'tool', 'api', 'cli', 'mcp'
  ];

  for (const keyword of techKeywords) {
    if (lowerContent.includes(keyword)) {
      tags.push(keyword.replace(/[^a-z0-9]/g, '-'));
    }
  }

  return [...new Set(tags)].slice(0, 10);
}

function extractDescription(content: string): string {
  // Try to get description from frontmatter or first meaningful paragraph
  const lines = content.split('\n');
  let description = '';
  let foundHeader = false;

  for (const line of lines) {
    const trimmed = line.trim();

    // Skip empty lines and headers at the start
    if (!trimmed) continue;
    if (trimmed.startsWith('#')) {
      foundHeader = true;
      continue;
    }

    // Skip code blocks and lists at the start
    if (trimmed.startsWith('```') || trimmed.startsWith('-') || trimmed.startsWith('*')) continue;

    // Get the first paragraph after any header
    if (foundHeader || description === '') {
      description = trimmed;
      break;
    }
  }

  return description.slice(0, 300) || 'OpenHands skill for AI-driven development';
}

function extractUseCases(content: string): string[] {
  const useCases: string[] = [];

  // Look for "When to Use" or similar sections
  const whenToUseMatch = content.match(/##?\s*(When to Use|Use Cases?|Usage)[^\n]*\n([\s\S]*?)(?=\n##|\n---|\n\*\*|$)/i);
  if (whenToUseMatch) {
    const lines = whenToUseMatch[2].split('\n').filter(l => l.trim().startsWith('-') || l.trim().startsWith('*'));
    for (const line of lines) {
      const useCase = line.replace(/^[-*]\s*/, '').trim();
      if (useCase && useCase.length > 5 && useCase.length < 200) {
        useCases.push(useCase);
      }
    }
  }

  return useCases.slice(0, 5);
}

function formatName(filename: string): string {
  return filename
    .replace(/\.md$/, '')
    .split(/[-_]/)
    .map(word => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ');
}

export async function scrapeOpenHandsSkills(): Promise<Skill[]> {
  console.log('🤖 Scraping OpenHands/OpenHands skills...');
  const skills: Skill[] = [];

  try {
    // Get skills directory contents
    const contents = await fetchGitHubContents(OPENHANDS_REPO, OPENHANDS_REPO.skillsPath!);

    // Filter markdown files (skills are individual .md files)
    const skillFiles = contents.filter(
      (item: GitHubContent) =>
        item.type === 'file' &&
        item.name.endsWith('.md') &&
        item.name !== 'README.md'
    );

    console.log(`  Found ${skillFiles.length} skill files`);

    for (const file of skillFiles) {
      try {
        const content = await fetchRawContent(OPENHANDS_REPO, file.path);
        const { data: frontmatter, content: markdownContent } = matter(content);

        const name = frontmatter.name || formatName(file.name);
        const description = frontmatter.description || extractDescription(markdownContent);
        const category = frontmatter.category || inferCategory(file.name, content);

        const skill: Skill = {
          id: `openhands-${slugify(file.name)}`,
          name,
          slug: slugify(file.name),
          description,
          category,
          source: 'openhands',
          repoUrl: `https://github.com/${OPENHANDS_REPO.owner}/${OPENHANDS_REPO.repo}`,
          skillUrl: getGitHubFileUrl(OPENHANDS_REPO, file.path),
          content: markdownContent.slice(0, 5000),
          tags: extractTags(content, name),
          useCases: extractUseCases(content),
          scrapedAt: new Date().toISOString(),
        };

        skills.push(skill);
        console.log(`  ✓ ${name}`);
      } catch (err) {
        console.log(`  ✗ Failed to process ${file.name}: ${(err as Error).message}`);
      }
    }

    console.log(`✓ Scraped ${skills.length} skills from OpenHands`);
  } catch (err) {
    console.error('Failed to scrape OpenHands:', err);
  }

  return skills;
}
