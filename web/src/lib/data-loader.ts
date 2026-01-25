import 'server-only';
import type { SkillsData, Skill } from '@/types/skill';

/**
 * Data Loading Configuration
 *
 * In development: Load from local files (public/data/)
 * In production:  Fetch from GitHub raw content
 *
 * Environment variables:
 * - USE_LOCAL_DATA=true   Force local data loading (useful for testing production build locally)
 * - GITHUB_DATA_REPO      Custom GitHub repo (default: encoreshao/awesome-skills)
 * - GITHUB_DATA_BRANCH    Custom branch (default: main)
 */

const GITHUB_REPO = process.env.GITHUB_DATA_REPO || 'encoreshao/awesome-skills';
const GITHUB_BRANCH = process.env.GITHUB_DATA_BRANCH || 'main';
const GITHUB_RAW_BASE = `https://raw.githubusercontent.com/${GITHUB_REPO}/${GITHUB_BRANCH}`;

// Cache for skills data
let cachedData: SkillsData | null = null;
let cacheTimestamp: number = 0;
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes cache in production

/**
 * Determine if we should use local data
 */
function shouldUseLocalData(): boolean {
  // Force local data via environment variable
  if (process.env.USE_LOCAL_DATA === 'true') {
    return true;
  }

  // Use local data in development mode
  if (process.env.NODE_ENV === 'development') {
    return true;
  }

  return false;
}

/**
 * Load skills data from local files (server-side only)
 */
async function loadLocalData(): Promise<SkillsData> {
  const fs = await import('fs');
  const path = await import('path');

  const dataPath = path.join(process.cwd(), 'public', 'data', 'skills.json');

  if (!fs.existsSync(dataPath)) {
    throw new Error(`Local data file not found: ${dataPath}`);
  }

  const content = fs.readFileSync(dataPath, 'utf-8');
  return JSON.parse(content);
}

/**
 * Fetch skills data from GitHub
 */
async function fetchGitHubData(): Promise<SkillsData> {
  const url = `${GITHUB_RAW_BASE}/data/skills.json`;

  const response = await fetch(url, {
    headers: {
      'Accept': 'application/json',
      'User-Agent': 'awesome-skills-web',
    },
    // Cache for 5 minutes
    next: { revalidate: 300 },
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch data from GitHub: ${response.status} ${response.statusText}`);
  }

  return response.json();
}

/**
 * Get skills data with caching
 * Uses local files in development, GitHub in production
 */
export async function getSkillsData(): Promise<SkillsData> {
  const now = Date.now();

  // Return cached data if still valid
  if (cachedData && (now - cacheTimestamp) < CACHE_TTL) {
    return cachedData;
  }

  try {
    if (shouldUseLocalData()) {
      console.log('[DataLoader] Loading from local files');
      cachedData = await loadLocalData();
    } else {
      console.log('[DataLoader] Fetching from GitHub:', GITHUB_REPO);
      cachedData = await fetchGitHubData();
    }

    cacheTimestamp = now;
    return cachedData!;
  } catch (error) {
    // Fallback: try local data if GitHub fetch fails
    if (!shouldUseLocalData()) {
      console.warn('[DataLoader] GitHub fetch failed, falling back to local data:', error);
      try {
        cachedData = await loadLocalData();
        cacheTimestamp = now;
        return cachedData!;
      } catch (localError) {
        console.error('[DataLoader] Local fallback also failed:', localError);
      }
    }
    throw error;
  }
}

/**
 * Get a single skill by slug
 */
export async function getSkillBySlug(slug: string): Promise<Skill | null> {
  const data = await getSkillsData();
  return data.skills.find((s) => s.slug === slug) || null;
}

/**
 * Get individual skill data (from individual JSON file)
 * Uses local files in development, GitHub in production
 */
export async function getSkillData(skillId: string): Promise<Skill | null> {
  try {
    if (shouldUseLocalData()) {
      const fs = await import('fs');
      const path = await import('path');

      const skillPath = path.join(process.cwd(), 'public', 'data', 'skills', `${skillId}.json`);

      if (!fs.existsSync(skillPath)) {
        return null;
      }

      const content = fs.readFileSync(skillPath, 'utf-8');
      return JSON.parse(content);
    } else {
      const url = `${GITHUB_RAW_BASE}/data/skills/${skillId}.json`;

      const response = await fetch(url, {
        headers: {
          'Accept': 'application/json',
          'User-Agent': 'awesome-skills-web',
        },
        next: { revalidate: 300 },
      });

      if (!response.ok) {
        return null;
      }

      return response.json();
    }
  } catch {
    return null;
  }
}

/**
 * Force refresh cached data
 */
export function invalidateCache(): void {
  cachedData = null;
  cacheTimestamp = 0;
}

/**
 * Get data source info for debugging
 */
export function getDataSourceInfo(): {
  source: 'local' | 'github';
  repo?: string;
  branch?: string;
} {
  if (shouldUseLocalData()) {
    return { source: 'local' };
  }
  return {
    source: 'github',
    repo: GITHUB_REPO,
    branch: GITHUB_BRANCH,
  };
}
