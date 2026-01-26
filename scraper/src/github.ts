import type { GitHubContent, GitHubRepo, GitHubRepoInfo } from './types.js';

const GITHUB_API_BASE = 'https://api.github.com';
const GITHUB_RAW_BASE = 'https://raw.githubusercontent.com';

// Configuration
const REQUEST_DELAY_MS = 100;  // Delay between requests to avoid bursting
const MAX_RETRIES = 3;
const RETRY_DELAY_MS = 2000;

// Rate limit tracking
let rateLimitRemaining = -1;
let rateLimitReset = 0;
let hasWarnedNoToken = false;

// Get GitHub token from environment for higher rate limits
function getGitHubToken(): string | undefined {
  return process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
}

function getGitHubHeaders(): Record<string, string> {
  const headers: Record<string, string> = {
    'Accept': 'application/vnd.github.v3+json',
    'User-Agent': 'awesome-skills-scraper',
  };

  // Use GITHUB_TOKEN if available (5000 requests/hour vs 60 for unauthenticated)
  const token = getGitHubToken();
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  } else if (!hasWarnedNoToken) {
    console.log('⚠️  No GITHUB_TOKEN set. Using unauthenticated API (60 req/hour limit).');
    console.log('   Set GITHUB_TOKEN for 5000 req/hour: export GITHUB_TOKEN=your_token\n');
    hasWarnedNoToken = true;
  }

  return headers;
}

// Update rate limit info from response headers
function updateRateLimitInfo(response: Response): void {
  const remaining = response.headers.get('x-ratelimit-remaining');
  const reset = response.headers.get('x-ratelimit-reset');
  
  if (remaining) {
    rateLimitRemaining = parseInt(remaining, 10);
  }
  if (reset) {
    rateLimitReset = parseInt(reset, 10);
  }
  
  // Warn when running low
  if (rateLimitRemaining >= 0 && rateLimitRemaining <= 10 && rateLimitRemaining % 5 === 0) {
    const resetDate = new Date(rateLimitReset * 1000);
    console.log(`⚠️  Rate limit low: ${rateLimitRemaining} requests remaining. Resets at ${resetDate.toLocaleTimeString()}`);
  }
}

// Sleep helper
function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// Check if we should wait for rate limit reset
async function checkRateLimit(): Promise<void> {
  if (rateLimitRemaining === 0) {
    const now = Math.floor(Date.now() / 1000);
    const waitSeconds = rateLimitReset - now;
    
    if (waitSeconds > 0 && waitSeconds < 300) { // Wait up to 5 minutes
      console.log(`⏳ Rate limit exceeded. Waiting ${waitSeconds} seconds for reset...`);
      await sleep(waitSeconds * 1000 + 1000); // Add 1 second buffer
    } else if (waitSeconds >= 300) {
      throw new Error(`Rate limit exceeded. Resets in ${Math.ceil(waitSeconds / 60)} minutes. Set GITHUB_TOKEN for higher limits.`);
    }
  }
}

// Fetch with retry and rate limit handling
async function fetchWithRetry(url: string, options: RequestInit, retries = MAX_RETRIES): Promise<Response> {
  await checkRateLimit();
  await sleep(REQUEST_DELAY_MS); // Small delay between requests
  
  const response = await fetch(url, options);
  updateRateLimitInfo(response);
  
  if (response.status === 403 && response.headers.get('x-ratelimit-remaining') === '0') {
    // Rate limited - wait and retry
    const resetTime = parseInt(response.headers.get('x-ratelimit-reset') || '0', 10);
    const now = Math.floor(Date.now() / 1000);
    const waitSeconds = resetTime - now;
    
    if (waitSeconds > 0 && waitSeconds < 300 && retries > 0) {
      console.log(`⏳ Rate limited. Waiting ${waitSeconds}s before retry...`);
      await sleep(waitSeconds * 1000 + 1000);
      return fetchWithRetry(url, options, retries - 1);
    }
    
    throw new Error(`rate limit exceeded`);
  }
  
  if (!response.ok && retries > 0 && response.status >= 500) {
    // Server error - retry with backoff
    await sleep(RETRY_DELAY_MS);
    return fetchWithRetry(url, options, retries - 1);
  }
  
  return response;
}

// Get current rate limit status
export function getRateLimitStatus(): { remaining: number; resetAt: Date | null } {
  return {
    remaining: rateLimitRemaining,
    resetAt: rateLimitReset > 0 ? new Date(rateLimitReset * 1000) : null,
  };
}

// Check rate limit before starting
export async function checkInitialRateLimit(): Promise<void> {
  try {
    const response = await fetch(`${GITHUB_API_BASE}/rate_limit`, {
      headers: getGitHubHeaders(),
    });
    
    if (response.ok) {
      const data = await response.json();
      const core = data.resources?.core;
      
      if (core) {
        rateLimitRemaining = core.remaining;
        rateLimitReset = core.reset;
        
        const limit = core.limit;
        const resetDate = new Date(rateLimitReset * 1000);
        
        console.log(`📊 GitHub API Rate Limit: ${rateLimitRemaining}/${limit} remaining`);
        
        if (rateLimitRemaining < 100) {
          console.log(`   ⚠️  Low rate limit! Resets at ${resetDate.toLocaleTimeString()}`);
        }
        
        if (limit === 60 && !getGitHubToken()) {
          console.log(`   💡 Tip: Set GITHUB_TOKEN for 5000 req/hour instead of 60`);
        }
        
        console.log('');
      }
    }
  } catch (err) {
    // Ignore errors checking rate limit
  }
}

export async function fetchRepoInfo(repo: GitHubRepo): Promise<GitHubRepoInfo> {
  const url = `${GITHUB_API_BASE}/repos/${repo.owner}/${repo.repo}`;

  const response = await fetchWithRetry(url, {
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

  const response = await fetchWithRetry(url, {
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
