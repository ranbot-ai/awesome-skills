import matter from 'gray-matter';
import { fetchGitHubContents, fetchRawContent, getGitHubUrl } from '../github.js';
import type { Skill, GitHubRepo, GitHubContent } from '../types.js';

export const SEQUENZY_REPO: GitHubRepo = {
  owner: 'Sequenzy',
  repo: 'skills',
  branch: 'main',
  skillsPath: 'skills',
};

function slugify(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '');
}

function titleFromSlug(slug: string): string {
  return slug
    .split('-')
    .map((word: string) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ');
}

function extractTags(content: string): string[] {
  const lowerContent = content.toLowerCase();
  const keywords = [
    'email', 'marketing', 'automation', 'campaigns', 'subscribers',
    'segments', 'sequences', 'templates', 'transactional', 'stats',
    'mcp', 'api', 'claude', 'codex', 'hermes'
  ];

  return keywords.filter((keyword) => lowerContent.includes(keyword)).slice(0, 10);
}

function extractUseCases(content: string): string[] {
  const useCases: string[] = [];
  const match = content.match(/##\s*(?:When to Use|Use Cases)[^\n]*\n([\s\S]*?)(?=\n##|\n---|$)/i);

  if (match) {
    const lines = match[1].split('\n').filter((line: string) => line.trim().startsWith('-'));
    for (const line of lines) {
      const useCase = line.replace(/^-\s*/, '').trim();
      if (useCase.length > 5 && useCase.length < 200) {
        useCases.push(useCase);
      }
    }
  }

  if (useCases.length === 0) {
    useCases.push(
      'Operate lifecycle email marketing workflows from AI agents',
      'Manage subscribers, segments, campaigns, sequences, templates, and stats'
    );
  }

  return useCases.slice(0, 5);
}

function extractInstructions(content: string): string | undefined {
  const match = content.match(/##\s*(?:Instructions|Workflow|How to Use)[^\n]*\n([\s\S]*?)(?=\n##|\n---|$)/i);
  return match ? match[1].trim().slice(0, 2000) : undefined;
}

export async function scrapeSequenzySkills(): Promise<Skill[]> {
  console.log('📧 Scraping Sequenzy/skills...');
  const skills: Skill[] = [];

  try {
    const contents = await fetchGitHubContents(SEQUENZY_REPO, SEQUENZY_REPO.skillsPath);
    const skillDirs = contents.filter((item: GitHubContent) => item.type === 'dir');

    console.log(`  Found ${skillDirs.length} potential skill directories`);

    for (const dir of skillDirs) {
      try {
        const dirContents = await fetchGitHubContents(SEQUENZY_REPO, dir.path);
        const skillFile = dirContents.find(
          (file: GitHubContent) => file.name.toLowerCase() === 'skill.md'
        );

        if (!skillFile) {
          continue;
        }

        const content = await fetchRawContent(SEQUENZY_REPO, skillFile.path);
        const { data: frontmatter, content: markdownContent } = matter(content);
        const name = frontmatter.name || titleFromSlug(dir.name);
        const description = frontmatter.description ||
          'Operate Sequenzy email marketing workflows from AI agents.';

        skills.push({
          id: `sequenzy-${dir.name}`,
          name,
          slug: slugify(name || dir.name),
          description,
          category: 'Business & Marketing',
          source: 'sequenzy',
          repoUrl: `https://github.com/${SEQUENZY_REPO.owner}/${SEQUENZY_REPO.repo}`,
          skillUrl: getGitHubUrl(SEQUENZY_REPO, dir.path),
          author: 'Sequenzy',
          authorUrl: 'https://github.com/Sequenzy',
          content: markdownContent.slice(0, 5000),
          tags: extractTags(content),
          useCases: extractUseCases(content),
          instructions: extractInstructions(content),
          scrapedAt: new Date().toISOString(),
        });

        console.log(`  ✓ ${name}`);
      } catch (err) {
        console.log(`  ✗ Failed to process ${dir.name}: ${(err as Error).message}`);
      }
    }

    console.log(`✓ Scraped ${skills.length} skills from Sequenzy`);
  } catch (err) {
    console.error('Failed to scrape Sequenzy:', err);
  }

  return skills;
}
