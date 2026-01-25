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
  scrapedAt: string;  // Date when this skill was first scraped
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
  newSkillCount?: number;  // Count of newly scraped skills this run
  stars?: number;  // GitHub repository stars
}

export interface ScrapedData {
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

export interface GitHubContent {
  name: string;
  path: string;
  sha: string;
  size: number;
  url: string;
  html_url: string;
  git_url: string;
  download_url: string | null;
  type: 'file' | 'dir';
}

export interface GitHubRepo {
  owner: string;
  repo: string;
  branch: string;
  skillsPath?: string;
}

export interface GitHubRepoInfo {
  stargazers_count: number;
  forks_count: number;
  description: string;
  html_url: string;
}
