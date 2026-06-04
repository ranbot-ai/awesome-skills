import matter from 'gray-matter';
import type { Skill, GitHubRepo, GitHubContent } from '../types.js';
import { fetchGitHubContents, fetchRawContent, getGitHubUrl } from '../github.js';

const SEQUENZY_REPO: GitHubRepo = {
  owner: 'Sequenzy',
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

function inferCategory(name: string, content: string): string {
  const lowerName = name.toLowerCase();
  const lowerContent = content.toLowerCase();

  if (
    lowerName.includes('email') ||
    lowerName.includes('marketing') ||
    lowerName.includes('sequenzy') ||
    lowerContent.includes('email marketing') ||
    lowerContent.includes('campaign') ||
    lowerContent.includes('lifecycle')
  ) {
    return 'Business & Marketing';
  }

  if (lowerContent.includes('api') || lowerContent.includes('automation')) {
    return 'Productivity & Organization';
  }

  return 'AI & Agents';
}

function extractTags(content: string, name: string): string[] {
  const tags: string[] = [];
  const lowerContent = content.toLowerCase();

  const keywords = [
    'email',
    'marketing',
    'automation',
    'campaigns',
    'subscribers',
    'templates',
    'transactional',
    'api',
    'sequenzy',
    'claude',
    'codex',
    'hermes',
    'agent',
  ];

  for (const keyword of keywords) {
    if (lowerContent.includes(keyword)) {
      tags.push(keyword);
    }
  }

  name.split('-').forEach(part => {
    if (part.length > 2 && !tags.includes(part)) {
      tags.push(part);
    }
  });

  return [...new Set(tags)].slice(0, 10);
}

function extractUseCases(content: string): string[] {
  const useCases: string[] = [];
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

    if (trimmed.startsWith('#')) {
      foundHeader = true;
      continue;
    }

    if (trimmed.startsWith('```') || trimmed.startsWith('-') || trimmed.startsWith('*')) continue;

    if (foundHeader || description === '') {
      description += (description ? ' ' : '') + trimmed;
      if (description.length > 100) break;
    }
  }

  return description.slice(0, 300) || 'Sequenzy skill for AI agents';
}

export async function scrapeSequenzySkills(): Promise<Skill[]> {
  console.log('📧 Scraping Sequenzy/skills...');
  const skills: Skill[] = [];

  try {
    const contents = await fetchGitHubContents(SEQUENZY_REPO, SEQUENZY_REPO.skillsPath || 'skills');
    const skillDirs = contents.filter(
      (item: GitHubContent) => item.type === 'dir' && !item.name.startsWith('.')
    );

    console.log(`  Found ${skillDirs.length} skill directories`);

    for (const dir of skillDirs) {
      try {
        const dirContents = await fetchGitHubContents(SEQUENZY_REPO, dir.path);
        const skillFile = dirContents.find(
          (f: GitHubContent) => f.name.toLowerCase() === 'skill.md' || f.name.toLowerCase() === 'readme.md'
        );

        if (skillFile) {
          const content = await fetchRawContent(SEQUENZY_REPO, skillFile.path);
          const { data: frontmatter, content: markdownContent } = matter(content);

          const name = frontmatter.name || dir.name.split('-').map((w: string) =>
            w.charAt(0).toUpperCase() + w.slice(1)
          ).join(' ');
          const description = extractDescription(markdownContent, frontmatter.description);
          const category = inferCategory(dir.name, content);

          const skill: Skill = {
            id: `sequenzy-${dir.name}`,
            name,
            slug: `sequenzy-${slugify(dir.name)}`,
            description,
            category,
            source: 'sequenzy',
            repoUrl: `https://github.com/${SEQUENZY_REPO.owner}/${SEQUENZY_REPO.repo}`,
            skillUrl: getGitHubUrl(SEQUENZY_REPO, dir.path),
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

    console.log(`✓ Scraped ${skills.length} skills from Sequenzy`);
  } catch (err) {
    console.error('Failed to scrape Sequenzy skills:', err);
  }

  return skills;
}

export { SEQUENZY_REPO };
