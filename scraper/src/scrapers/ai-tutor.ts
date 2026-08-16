import matter from 'gray-matter';
import type { Skill, GitHubRepo, GitHubContent } from '../types.js';
import { fetchGitHubContents, fetchRawContent, getGitHubUrl } from '../github.js';

const AI_TUTOR_REPO: GitHubRepo = {
  owner: 'zv38',
  repo: 'ai-tutor',
  branch: 'main',
  skillsPath: 'skills',
};

function slugify(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
}

function titleCase(name: string): string {
  return name
    .split('-')
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(' ');
}

function extractTags(content: string, name: string): string[] {
  const tags: string[] = [];
  const lowerContent = content.toLowerCase();
  const keywords = [
    'claude', 'ai', 'agent', 'llm', 'skill',
    'tutor', 'tutoring', 'education', 'learning', 'study',
    'teaching', 'teach', 'quiz', 'exam', 'test',
    'mistake', 'review', 'forgetting-curve', 'spaced-repetition',
    'math', 'physics', 'chemistry', 'biology', 'english',
    'history', 'geography', 'markdown', 'node', 'cli', 'json',
    'plan', 'practice', 'homework'
  ];
  for (const keyword of keywords) {
    if (lowerContent.includes(keyword)) {
      tags.push(keyword);
    }
  }
  // Add meaningful name parts as tags
  name.toLowerCase().split('-').forEach((part) => {
    if (part.length > 2 && !tags.includes(part)) {
      tags.push(part);
    }
  });
  return [...new Set(tags)].slice(0, 10);
}

function extractUseCases(content: string): string[] {
  const useCases: string[] = [];
  // Look for English "When to Use / Use Cases / Examples" sections
  const enMatch = content.match(/##?\s*(When to Use|Use Cases?|Examples?)[^\n]*\n([\s\S]*?)(?=\n##|\n---|\n\*\*|$)/i);
  // Look for Chinese trigger sections (触发场景 / 触发条件 / 用途)
  const zhMatch = content.match(/##?\s*(触发场景|触发条件|用途|使用场景)[^\n]*\n([\s\S]*?)(?=\n##|\n---|\n\*\*|$)/);
  const match = zhMatch || enMatch;
  if (match) {
    const lines = match[2].split('\n');
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
  return description.slice(0, 300) || 'AI learning tutor skill';
}

async function processSkillFile(
  filePath: string,
  dirName: string,
  idPrefix: string,
  isRoot: boolean
): Promise<Skill | null> {
  try {
    const content = await fetchRawContent(AI_TUTOR_REPO, filePath);
    const { data: frontmatter, content: markdownContent } = matter(content);
    const slug = idPrefix ? `${idPrefix}-${slugify(dirName)}` : slugify(dirName);
    const name = isRoot
      ? 'AI Tutor'
      : (frontmatter.name && frontmatter.name.includes(' '))
        ? frontmatter.name
        : titleCase(dirName);
    const description = extractDescription(markdownContent, frontmatter.description);
    return {
      id: slug,
      name,
      slug,
      description,
      category: 'AI & Agents',
      source: 'ai-tutor',
      repoUrl: `https://github.com/${AI_TUTOR_REPO.owner}/${AI_TUTOR_REPO.repo}`,
      skillUrl: getGitHubUrl(AI_TUTOR_REPO, filePath),
      content: markdownContent.slice(0, 5000),
      tags: extractTags(content, dirName),
      useCases: extractUseCases(content),
      scrapedAt: new Date().toISOString(),
    };
  } catch (err) {
    console.log(`  ✗ Failed to process ${dirName}: ${(err as Error).message}`);
    return null;
  }
}

export async function scrapeAiTutorSkills(): Promise<Skill[]> {
  console.log('📚 Scraping zv38/ai-tutor...');
  const skills: Skill[] = [];
  try {
    // 1) Root-level SKILL.md (the main skill pack entry)
    const rootContents = await fetchGitHubContents(AI_TUTOR_REPO, '');
    const rootSkillFile = rootContents.find(
      (f: GitHubContent) => f.name.toLowerCase() === 'skill.md'
    );
    if (rootSkillFile) {
      const rootSkill = await processSkillFile(rootSkillFile.path, 'ai-tutor', '', true);
      if (rootSkill) {
        skills.push(rootSkill);
        console.log(`  ✓ ${rootSkill.name}`);
      }
    }

    // 2) Sub-skills under skills/
    const subContents = await fetchGitHubContents(AI_TUTOR_REPO, AI_TUTOR_REPO.skillsPath!);
    const skillDirs = subContents.filter(
      (item: GitHubContent) => item.type === 'dir' && !item.name.startsWith('.')
    );
    console.log(`  Found ${skillDirs.length} sub-skill directories`);
    for (const dir of skillDirs) {
      try {
        const dirContents = await fetchGitHubContents(AI_TUTOR_REPO, dir.path);
        const skillFile = dirContents.find(
          (f: GitHubContent) => f.name.toLowerCase() === 'skill.md'
        );
        if (skillFile) {
          const subSkill = await processSkillFile(skillFile.path, dir.name, 'ai-tutor', false);
          if (subSkill) {
            skills.push(subSkill);
            console.log(`  ✓ ${subSkill.name}`);
          }
        }
      } catch (err) {
        console.log(`  ✗ Failed to process ${dir.name}: ${(err as Error).message}`);
      }
    }
    console.log(`✓ Scraped ${skills.length} skills from AI Tutor`);
  } catch (err) {
    console.error('Failed to scrape AI Tutor:', err);
  }
  return skills;
}

export { AI_TUTOR_REPO };
