import matter from 'gray-matter';
import type { Skill, GitHubRepo, GitHubContent } from '../types.js';
import { fetchGitHubContents, fetchRawContent, getGitHubUrl } from '../github.js';

export const ACCINT_REPO: GitHubRepo = {
  owner: 'maxbaluev',
  repo: 'accreted-intelligence',
  branch: 'main',
  skillsPath: 'plugins/claude/skills',
};

function slugify(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
}

function formatName(name: string): string {
  return name
    .split(/[-_]/)
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ');
}

function extractTags(content: string, name: string): string[] {
  const tags: string[] = ['accint', 'memory', 'agent', 'mcp', 'claude'];
  const lowerContent = content.toLowerCase();
  const lowerName = name.toLowerCase();

  const keywords = [
    'codex',
    'commitment',
    'outcome',
    'frame',
    'solve',
    'retrieve',
    'workflow',
    'local-first',
    'scored-memory',
  ];

  for (const keyword of keywords) {
    if (lowerName.includes(keyword) || lowerContent.includes(keyword)) {
      tags.push(keyword);
    }
  }

  return [...new Set(tags)].slice(0, 10);
}

function extractUseCases(name: string): string[] {
  const lowerName = name.toLowerCase();

  if (lowerName.includes('solve')) {
    return [
      'Route coding-agent goals through AccInt scored memory',
      'Resolve returned deliberation frames before continuing work',
    ];
  }

  if (lowerName.includes('commitment')) {
    return [
      'Review open AccInt commitments',
      'Record honest outcome feedback after tests or real-world replies',
    ];
  }

  if (lowerName.includes('frame')) {
    return [
      'Drain checkpointed AccInt brain frames',
      'Submit reasoned continuation proposals back to the memory loop',
    ];
  }

  return ['Use AccInt MCP memory workflows from Claude-compatible agents'];
}

export async function scrapeAccIntSkills(): Promise<Skill[]> {
  console.log('Scraping maxbaluev/accreted-intelligence skills...');
  const skills: Skill[] = [];

  try {
    const contents = await fetchGitHubContents(ACCINT_REPO, ACCINT_REPO.skillsPath!);
    const skillDirs = contents.filter(
      (item: GitHubContent) => item.type === 'dir' && !item.name.startsWith('.')
    );

    console.log(`  Found ${skillDirs.length} skill directories`);

    for (const dir of skillDirs) {
      try {
        const dirContents = await fetchGitHubContents(ACCINT_REPO, dir.path);
        const skillFile = dirContents.find(
          (file: GitHubContent) => file.name.toLowerCase() === 'skill.md'
        );

        if (!skillFile) {
          continue;
        }

        const content = await fetchRawContent(ACCINT_REPO, skillFile.path);
        const { data: frontmatter, content: markdownContent } = matter(content);
        const baseName = frontmatter.name || dir.name;
        const name = `AccInt ${formatName(baseName)}`;
        const description =
          frontmatter.description ||
          `${name} skill for MCP-backed agent memory workflows`;

        const skill: Skill = {
          id: `accint-${dir.name}`,
          name,
          slug: `accint-${slugify(dir.name)}`,
          description,
          category: 'AI & Agents',
          source: 'accint',
          repoUrl: `https://github.com/${ACCINT_REPO.owner}/${ACCINT_REPO.repo}`,
          skillUrl: getGitHubUrl(ACCINT_REPO, dir.path),
          content: markdownContent.slice(0, 5000),
          tags: extractTags(content, baseName),
          useCases: extractUseCases(baseName),
          scrapedAt: new Date().toISOString(),
        };

        skills.push(skill);
        console.log(`  - ${name}`);
      } catch (err) {
        console.log(`  Failed to process ${dir.name}: ${(err as Error).message}`);
      }
    }

    console.log(`Scraped ${skills.length} skills from AccInt`);
  } catch (err) {
    console.error('Failed to scrape AccInt:', err);
  }

  return skills;
}
