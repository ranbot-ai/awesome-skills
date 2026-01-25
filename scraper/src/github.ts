import type { GitHubContent, GitHubRepo, GitHubRepoInfo } from './types.js';

const GITHUB_API_BASE = 'https://api.github.com';
const GITHUB_RAW_BASE = 'https://raw.githubusercontent.com';

// Get GitHub token from environment for higher rate limits
function getGitHubHeaders(): Record<string, string> {
  const headers: Record<string, string> = {
    'Accept': 'application/vnd.github.v3+json',
    'User-Agent': 'awesome-skills-scraper',
  };

  // Use GITHUB_TOKEN if available (5000 requests/hour vs 60 for unauthenticated)
  const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  return headers;
}

export async function fetchRepoInfo(repo: GitHubRepo): Promise<GitHubRepoInfo> {
  const url = `${GITHUB_API_BASE}/repos/${repo.owner}/${repo.repo}`;

  const response = await fetch(url, {
    headers: getGitHubHeaders(),
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch repo info ${url}: ${response.statusText}`);
  }

  return response.json();
}

export async function fetchGitHubContents(
  repo: GitHubRepo,
  path: string = ''
): Promise<GitHubContent[]> {
  const url = `${GITHUB_API_BASE}/repos/${repo.owner}/${repo.repo}/contents/${path}?ref=${repo.branch}`;

  const response = await fetch(url, {
    headers: getGitHubHeaders(),
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch ${url}: ${response.statusText}`);
  }

  const data = await response.json();
  return Array.isArray(data) ? data : [data];
}

export async function fetchRawContent(
  repo: GitHubRepo,
  path: string
): Promise<string> {
  const url = `${GITHUB_RAW_BASE}/${repo.owner}/${repo.repo}/${repo.branch}/${path}`;

  const headers: Record<string, string> = {
    'User-Agent': 'awesome-skills-scraper',
  };

  // Add token for raw content too (helps with private repos)
  const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const response = await fetch(url, { headers });

  if (!response.ok) {
    throw new Error(`Failed to fetch ${url}: ${response.statusText}`);
  }

  return response.text();
}

export function getGitHubUrl(repo: GitHubRepo, path: string): string {
  return `https://github.com/${repo.owner}/${repo.repo}/tree/${repo.branch}/${path}`;
}

export function getGitHubFileUrl(repo: GitHubRepo, path: string): string {
  return `https://github.com/${repo.owner}/${repo.repo}/blob/${repo.branch}/${path}`;
}
