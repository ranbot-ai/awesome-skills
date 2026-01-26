import matter from 'gray-matter';
import type { Skill, GitHubRepo, GitHubContent } from '../types.js';
import { fetchGitHubContents, fetchRawContent, getGitHubUrl } from '../github.js';

const ANTIGRAVITY_REPO: GitHubRepo = {
  owner: 'sickn33',
  repo: 'antigravity-awesome-skills',
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
  // Autonomous & Agentic
  'loki-mode': 'AI & Agents',
  'subagent-driven-development': 'AI & Agents',
  'dispatching-parallel-agents': 'AI & Agents',
  'planning-with-files': 'AI & Agents',
  'skill-creator': 'AI & Agents',
  'skill-developer': 'AI & Agents',
  // Development
  'tdd-workflow': 'Development & Code Tools',
  'systematic-debugging': 'Development & Code Tools',
  'react-patterns': 'Development & Code Tools',
  'backend-dev-guidelines': 'Development & Code Tools',
  'frontend-dev-guidelines': 'Development & Code Tools',
  'senior-fullstack': 'Development & Code Tools',
  'software-architecture': 'Development & Code Tools',
  // Cybersecurity
  'ethical-hacking-methodology': 'Security & Systems',
  'metasploit-framework': 'Security & Systems',
  'burp-suite-testing': 'Security & Systems',
  'sql-injection-testing': 'Security & Systems',
  'active-directory-attacks': 'Security & Systems',
  'aws-penetration-testing': 'Security & Systems',
  'cloud-penetration-testing': 'Security & Systems',
  'red-team-tactics': 'Security & Systems',
  // Creative & Design
  'ui-ux-pro-max': 'Creative & Media',
  'frontend-design': 'Creative & Media',
  'canvas-design': 'Creative & Media',
  'algorithmic-art': 'Creative & Media',
  'theme-factory': 'Creative & Media',
  // Marketing
  'page-cro': 'Business & Marketing',
  'copywriting': 'Business & Marketing',
  'seo-audit': 'Business & Marketing',
  'paid-ads': 'Business & Marketing',
  'email-sequence': 'Business & Marketing',
  'pricing-strategy': 'Business & Marketing',
  'launch-strategy': 'Business & Marketing',
  // Integrations
  'stripe-integration': 'Development & Code Tools',
  'firebase': 'Development & Code Tools',
  'supabase': 'Development & Code Tools',
  'clerk-auth': 'Development & Code Tools',
  'discord-bot-architect': 'Development & Code Tools',
  'slack-bot-builder': 'Development & Code Tools',
  // Document Processing
  'docx': 'Document Processing',
  'pdf': 'Document Processing',
  'pptx': 'Document Processing',
  'xlsx': 'Document Processing',
};

function inferCategory(name: string, content: string): string {
  // Check direct mapping first
  if (CATEGORY_MAPPING[name]) {
    return CATEGORY_MAPPING[name];
  }

  const lowerName = name.toLowerCase();
  const lowerContent = content.toLowerCase();

  // Security
  if (lowerName.includes('pentest') || lowerName.includes('security') ||
      lowerName.includes('hack') || lowerName.includes('exploit') ||
      lowerName.includes('vuln') || lowerName.includes('attack') ||
      lowerContent.includes('penetration') || lowerContent.includes('vulnerability')) {
    return 'Security & Systems';
  }

  // AI & Agents
  if (lowerName.includes('agent') || lowerName.includes('llm') ||
      lowerName.includes('langgraph') || lowerName.includes('crewai') ||
      lowerContent.includes('multi-agent') || lowerContent.includes('autonomous')) {
    return 'AI & Agents';
  }

  // Document processing
  if (lowerName.includes('doc') || lowerName.includes('pdf') ||
      lowerName.includes('ppt') || lowerName.includes('xlsx') ||
      lowerContent.includes('document') || lowerContent.includes('spreadsheet')) {
    return 'Document Processing';
  }

  // Creative
  if (lowerName.includes('design') || lowerName.includes('art') ||
      lowerName.includes('ui') || lowerName.includes('ux') ||
      lowerContent.includes('creative') || lowerContent.includes('visual')) {
    return 'Creative & Media';
  }

  // Development
  if (lowerName.includes('code') || lowerName.includes('dev') ||
      lowerName.includes('test') || lowerName.includes('mcp') ||
      lowerName.includes('api') || lowerName.includes('typescript') ||
      lowerContent.includes('developer') || lowerContent.includes('programming')) {
    return 'Development & Code Tools';
  }

  // Marketing
  if (lowerName.includes('seo') || lowerName.includes('market') ||
      lowerName.includes('cro') || lowerName.includes('copy') ||
      lowerContent.includes('conversion') || lowerContent.includes('marketing')) {
    return 'Business & Marketing';
  }

  // Game Development
  if (lowerName.includes('game') || lowerContent.includes('game development')) {
    return 'Creative & Media';
  }

  return 'AI & Agents';
}

function extractTags(content: string, name: string): string[] {
  const tags: string[] = [];
  const lowerContent = content.toLowerCase();

  const techKeywords = [
    'python', 'javascript', 'typescript', 'react', 'node', 'nextjs',
    'pdf', 'docx', 'xlsx', 'pptx', 'markdown',
    'api', 'mcp', 'claude', 'ai', 'agent', 'llm', 'gpt',
    'automation', 'workflow', 'template', 'design',
    'document', 'spreadsheet', 'presentation', 'image',
    'security', 'pentest', 'hacking', 'vulnerability',
    'tailwind', 'prisma', 'supabase', 'firebase', 'stripe',
    'docker', 'kubernetes', 'aws', 'gcp', 'azure',
    'langgraph', 'langchain', 'crewai', 'rag',
    'seo', 'cro', 'marketing', 'copywriting'
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

  // Look for "Examples" or "Use Cases" or "When to Use" sections
  const examplesMatch = content.match(/##?\s*(Examples?|Use Cases?|When to Use|TRIGGER)[^\n]*\n([\s\S]*?)(?=\n##|\n---|\n\*\*|$)/i);

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

  return description.slice(0, 300) || 'Antigravity skill for Claude Code';
}

async function processSkillDirectory(
  dirPath: string,
  dirName: string,
  isNested: boolean = false
): Promise<Skill[]> {
  const skills: Skill[] = [];

  try {
    const dirContents = await fetchGitHubContents(ANTIGRAVITY_REPO, dirPath);

    // Look for SKILL.md in this directory
    const skillFile = dirContents.find(
      (f: GitHubContent) => f.name.toLowerCase() === 'skill.md'
    );

    if (skillFile) {
      const content = await fetchRawContent(ANTIGRAVITY_REPO, skillFile.path);
      const { data: frontmatter, content: markdownContent } = matter(content);

      const name = frontmatter.name || dirName.split('-').map((w: string) =>
        w.charAt(0).toUpperCase() + w.slice(1)
      ).join(' ');

      const description = extractDescription(markdownContent, frontmatter.description);
      const category = inferCategory(dirName, content);

      const skill: Skill = {
        id: `antigravity-${dirName}`,
        name,
        slug: slugify(dirName),
        description,
        category,
        source: 'antigravity',
        repoUrl: `https://github.com/${ANTIGRAVITY_REPO.owner}/${ANTIGRAVITY_REPO.repo}`,
        skillUrl: getGitHubUrl(ANTIGRAVITY_REPO, dirPath),
        content: markdownContent.slice(0, 5000),
        tags: extractTags(content, name),
        useCases: extractUseCases(content),
        scrapedAt: new Date().toISOString(),
      };

      skills.push(skill);
      console.log(`  ✓ ${name}`);
    }

    // Also check for nested skill directories (like game-development/2d-games)
    if (!isNested) {
      const subDirs = dirContents.filter(
        (item: GitHubContent) =>
          item.type === 'dir' &&
          !item.name.startsWith('.')
      );

      for (const subDir of subDirs) {
        const nestedSkills = await processSkillDirectory(
          subDir.path,
          `${dirName}-${subDir.name}`,
          true
        );
        skills.push(...nestedSkills);
      }
    }
  } catch (err) {
    console.log(`  ✗ Failed to process ${dirName}: ${(err as Error).message}`);
  }

  return skills;
}

export async function scrapeAntigravitySkills(): Promise<Skill[]> {
  console.log('🌌 Scraping sickn33/antigravity-awesome-skills...');
  const skills: Skill[] = [];

  try {
    // Get skills directory contents
    const contents = await fetchGitHubContents(ANTIGRAVITY_REPO, ANTIGRAVITY_REPO.skillsPath!);

    // Filter directories (skills are in subdirectories)
    const skillDirs = contents.filter(
      (item: GitHubContent) =>
        item.type === 'dir' &&
        !item.name.startsWith('.')
    );

    console.log(`  Found ${skillDirs.length} skill directories`);

    for (const dir of skillDirs) {
      const dirSkills = await processSkillDirectory(dir.path, dir.name);
      skills.push(...dirSkills);
    }

    console.log(`✓ Scraped ${skills.length} skills from Antigravity`);
  } catch (err) {
    console.error('Failed to scrape Antigravity:', err);
  }

  return skills;
}

export { ANTIGRAVITY_REPO };
