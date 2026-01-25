export interface Skill {
  id: string;
  name: string;
  slug: string;
  description: string;
  category: string;
  source: 'composio' | 'openhands' | 'anthropic' | 'superpowers' | 'awesome-llm';
  repoUrl: string;
  skillUrl: string;
  author?: string;
  authorUrl?: string;
  content?: string;
  tags: string[];
  useCases: string[];
  instructions?: string;
  examples?: string[];
  createdAt?: string;
  updatedAt?: string;
  scrapedAt: string;
}

export interface SkillCategory {
  id: string;
  name: string;
  description: string;
  icon: string;
  count: number;
}

export interface SourceInfo {
  name: string;
  url: string;
  skillCount: number;
  newSkillCount?: number;
  stars?: number;
}

export interface SkillsData {
  skills: Skill[];
  categories: SkillCategory[];
  sources: SourceInfo[];
  lastUpdated: string;
  stats: {
    totalSkills: number;
    newSkills: number;
    scrapedAt: string;
  };
}
