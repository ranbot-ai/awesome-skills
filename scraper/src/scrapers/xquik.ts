import matter from 'gray-matter';
import { fetchRawContent, getGitHubFileUrl } from '../github.js';
import type { Skill, GitHubRepo } from '../types.js';

export const XQUIK_REPO: GitHubRepo = {
  owner: 'Xquik-dev',
  repo: 'x-twitter-scraper',
  branch: 'master',
  skillsPath: 'skills/x-twitter-scraper',
};

function extractUseCases(content: string): string[] {
  const useCases: string[] = [];
  const match = content.match(/##\s*When to Use[^\n]*\n([\s\S]*?)(?=\n##|\n---|$)/i);

  if (!match) {
    return useCases;
  }

  const lines = match[1].split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed.startsWith('-')) {
      continue;
    }

    const useCase = trimmed.replace(/^-\s*/, '').trim();
    if (useCase.length > 10 && useCase.length < 200) {
      useCases.push(useCase);
    }
  }

  return useCases.slice(0, 5);
}

export async function scrapeXquikSkills(): Promise<Skill[]> {
  console.log('🔎 Scraping Xquik-dev/x-twitter-scraper...');

  try {
    const skillPath = `${XQUIK_REPO.skillsPath}/SKILL.md`;
    const content = await fetchRawContent(XQUIK_REPO, skillPath);
    const { data: frontmatter, content: markdownContent } = matter(content);

    const skill: Skill = {
      id: 'xquik-x-twitter-scraper',
      name: frontmatter.name || 'Xquik X Data',
      slug: 'x-twitter-scraper',
      description:
        frontmatter.description ||
        'Use Xquik for X data workflows from AI coding agents.',
      category: 'Data & Analysis',
      source: 'xquik',
      repoUrl: `https://github.com/${XQUIK_REPO.owner}/${XQUIK_REPO.repo}`,
      skillUrl: getGitHubFileUrl(XQUIK_REPO, skillPath),
      content: markdownContent.slice(0, 5000),
      tags: ['x', 'api', 'mcp', 'agent', 'automation'],
      useCases: extractUseCases(markdownContent),
      scrapedAt: new Date().toISOString(),
    };

    console.log('  ✓ Xquik X Data');
    console.log('✓ Scraped 1 skill from Xquik');
    return [skill];
  } catch (err) {
    console.error('Failed to scrape Xquik:', err);
    return [];
  }
}
