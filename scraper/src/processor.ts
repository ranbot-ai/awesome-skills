import type { Skill, SkillCategory, ScrapedData, SourceInfo } from './types.js';

export interface RepoStars {
  composio: number;
  openhands: number;
  anthropic: number;
  superpowers: number;
  awesomeLlm: number;
}

const CATEGORY_ICONS: Record<string, string> = {
  'Document Processing': 'file-text',
  'Development & Code Tools': 'code',
  'Data & Analysis': 'bar-chart',
  'Business & Marketing': 'briefcase',
  'Communication & Writing': 'message-circle',
  'Creative & Media': 'palette',
  'Productivity & Organization': 'folder',
  'Collaboration & Project Management': 'users',
  'Security & Systems': 'shield',
  'AI & Agents': 'bot',
};

const CATEGORY_DESCRIPTIONS: Record<string, string> = {
  'Document Processing': 'Create, edit, and analyze documents including Word, PDF, PowerPoint, and Excel files.',
  'Development & Code Tools': 'Tools for building, testing, and deploying software with AI assistance.',
  'Data & Analysis': 'Analyze data, run queries, and generate insights from various data sources.',
  'Business & Marketing': 'Skills for marketing, branding, lead generation, and business operations.',
  'Communication & Writing': 'Content creation, writing assistance, and communication tools.',
  'Creative & Media': 'Design, image editing, video processing, and creative content generation.',
  'Productivity & Organization': 'File management, task organization, and workflow automation.',
  'Collaboration & Project Management': 'Team collaboration, version control, and project management.',
  'Security & Systems': 'Security analysis, system administration, and forensics.',
  'AI & Agents': 'AI agent development, memory systems, and autonomous workflows.',
};

export function processSkills(
  skills: Skill[],
  existingSkills: Skill[] = [],
  stars: RepoStars = { composio: 0, openhands: 0, anthropic: 0, superpowers: 0, awesomeLlm: 0 }
): ScrapedData {
  const scrapedAt = new Date().toISOString();

  // Create a map of existing skills by ID to preserve their original scrapedAt date
  const existingSkillMap = new Map<string, Skill>();
  for (const skill of existingSkills) {
    existingSkillMap.set(skill.id, skill);
  }

  // Track new skills count per source
  const newSkillsBySource = new Map<string, number>();
  let totalNewSkills = 0;

  // Deduplicate skills by slug and merge with existing data
  const skillMap = new Map<string, Skill>();
  for (const skill of skills) {
    const existingSkill = skillMap.get(skill.slug);
    const previouslyScrapedSkill = existingSkillMap.get(skill.id);

    // Check if this is a new skill (not in existing data)
    if (!previouslyScrapedSkill) {
      totalNewSkills++;
      const sourceCount = newSkillsBySource.get(skill.source) || 0;
      newSkillsBySource.set(skill.source, sourceCount + 1);
    }

    if (!existingSkill || (skill.content?.length || 0) > (existingSkill.content?.length || 0)) {
      // Preserve the original scrapedAt date if skill existed before
      const finalSkill: Skill = {
        ...skill,
        scrapedAt: previouslyScrapedSkill?.scrapedAt || skill.scrapedAt || scrapedAt,
      };
      skillMap.set(skill.slug, finalSkill);
    }
  }

  const uniqueSkills = Array.from(skillMap.values());

  // Sort skills by name
  uniqueSkills.sort((a, b) => a.name.localeCompare(b.name));

  // Generate categories
  const categoryCount = new Map<string, number>();
  for (const skill of uniqueSkills) {
    const count = categoryCount.get(skill.category) || 0;
    categoryCount.set(skill.category, count + 1);
  }

  const categories: SkillCategory[] = Array.from(categoryCount.entries())
    .map(([name, count]) => ({
      id: name.toLowerCase().replace(/[^a-z0-9]+/g, '-'),
      name,
      description: CATEGORY_DESCRIPTIONS[name] || `Skills related to ${name}`,
      icon: CATEGORY_ICONS[name] || 'folder',
      count,
    }))
    .sort((a, b) => b.count - a.count);

  // Generate source statistics with new skill counts
  const sourceCount = new Map<string, number>();
  for (const skill of uniqueSkills) {
    const count = sourceCount.get(skill.source) || 0;
    sourceCount.set(skill.source, count + 1);
  }

  const sources: SourceInfo[] = [
    {
      name: 'Superpowers',
      url: 'https://github.com/obra/superpowers',
      skillCount: sourceCount.get('superpowers') || 0,
      newSkillCount: newSkillsBySource.get('superpowers') || 0,
      stars: stars.superpowers,
    },
    {
      name: 'Anthropic',
      url: 'https://github.com/anthropics/skills',
      skillCount: sourceCount.get('anthropic') || 0,
      newSkillCount: newSkillsBySource.get('anthropic') || 0,
      stars: stars.anthropic,
    },
    {
      name: 'ComposioHQ',
      url: 'https://github.com/ComposioHQ/awesome-claude-skills',
      skillCount: sourceCount.get('composio') || 0,
      newSkillCount: newSkillsBySource.get('composio') || 0,
      stars: stars.composio,
    },
    {
      name: 'OpenHands',
      url: 'https://github.com/OpenHands/OpenHands',
      skillCount: sourceCount.get('openhands') || 0,
      newSkillCount: newSkillsBySource.get('openhands') || 0,
      stars: stars.openhands,
    },
    {
      name: 'Awesome LLM',
      url: 'https://github.com/Prat011/awesome-llm-skills',
      skillCount: sourceCount.get('awesome-llm') || 0,
      newSkillCount: newSkillsBySource.get('awesome-llm') || 0,
      stars: stars.awesomeLlm,
    },
  ];

  return {
    skills: uniqueSkills,
    categories,
    sources,
    lastUpdated: scrapedAt,
    stats: {
      totalSkills: uniqueSkills.length,
      newSkills: totalNewSkills,
      scrapedAt,
    },
  };
}

export function generateSearchIndex(skills: Skill[]): Record<string, string[]> {
  const index: Record<string, string[]> = {};

  for (const skill of skills) {
    const keywords = new Set<string>();

    // Add name words
    skill.name.toLowerCase().split(/\s+/).forEach(w => keywords.add(w));

    // Add description words
    skill.description.toLowerCase().split(/\s+/).forEach(w => {
      if (w.length > 3) keywords.add(w);
    });

    // Add tags
    skill.tags.forEach(t => keywords.add(t.toLowerCase()));

    // Add category
    skill.category.toLowerCase().split(/\s+/).forEach(w => keywords.add(w));

    index[skill.id] = Array.from(keywords);
  }

  return index;
}
