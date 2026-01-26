import { writeFileSync, mkdirSync, existsSync, readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { scrapeComposioSkills, COMPOSIO_REPO } from './scrapers/composio.js';
import { scrapeOpenHandsSkills, OPENHANDS_REPO } from './scrapers/openhands.js';
import { scrapeAnthropicSkills, ANTHROPIC_REPO } from './scrapers/anthropic.js';
import { scrapeSuperPowersSkills, SUPERPOWERS_REPO } from './scrapers/superpowers.js';
import { scrapeAwesomeLLMSkills, AWESOME_LLM_REPO } from './scrapers/awesome-llm.js';
import { scrapeAntigravitySkills, ANTIGRAVITY_REPO } from './scrapers/antigravity.js';
import { processSkills, generateSearchIndex, type RepoStars } from './processor.js';
import { fetchRepoInfo, checkInitialRateLimit } from './github.js';
import type { Skill, ScrapedData, GitHubRepo } from './types.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const OUTPUT_DIR = join(__dirname, '../../data');

function loadExistingSkills(): Skill[] {
  const dataPath = join(OUTPUT_DIR, 'skills.json');
  if (existsSync(dataPath)) {
    try {
      const data: ScrapedData = JSON.parse(readFileSync(dataPath, 'utf-8'));
      console.log(`📂 Loaded ${data.skills.length} existing skills from previous scrape`);
      return data.skills;
    } catch (err) {
      console.log('⚠️  Could not load existing skills data, starting fresh');
    }
  }
  return [];
}

async function fetchStars(repo: GitHubRepo): Promise<number> {
  try {
    const info = await fetchRepoInfo(repo);
    return info.stargazers_count;
  } catch (err) {
    console.log(`  ⚠️  Could not fetch stars for ${repo.owner}/${repo.repo}`);
    return 0;
  }
}

async function main() {
  console.log('🚀 Starting Agent Skills Scraper\n');
  console.log('='.repeat(50));

  // Check GitHub API rate limit status
  await checkInitialRateLimit();

  // Load existing skills to preserve scrapedAt dates
  const existingSkills = loadExistingSkills();
  console.log('');

  // Fetch repository stars
  console.log('⭐ Fetching repository stars...');
  const stars: RepoStars = {
    superpowers: await fetchStars(SUPERPOWERS_REPO),
    anthropic: await fetchStars(ANTHROPIC_REPO),
    composio: await fetchStars(COMPOSIO_REPO),
    openhands: await fetchStars(OPENHANDS_REPO),
    awesomeLlm: await fetchStars(AWESOME_LLM_REPO),
    antigravity: await fetchStars(ANTIGRAVITY_REPO),
  };
  console.log(`  • Superpowers: ${stars.superpowers.toLocaleString()} stars`);
  console.log(`  • Anthropic: ${stars.anthropic.toLocaleString()} stars`);
  console.log(`  • ComposioHQ: ${stars.composio.toLocaleString()} stars`);
  console.log(`  • OpenHands: ${stars.openhands.toLocaleString()} stars`);
  console.log(`  • Awesome LLM: ${stars.awesomeLlm.toLocaleString()} stars`);
  console.log(`  • Antigravity: ${stars.antigravity.toLocaleString()} stars`);
  console.log('');

  const allSkills: Skill[] = [];

  // Scrape from all sources
  try {
    const superpowersSkills = await scrapeSuperPowersSkills();
    allSkills.push(...superpowersSkills);
  } catch (err) {
    console.error('Error scraping Superpowers:', err);
  }

  console.log('');

  try {
    const anthropicSkills = await scrapeAnthropicSkills();
    allSkills.push(...anthropicSkills);
  } catch (err) {
    console.error('Error scraping Anthropic:', err);
  }

  console.log('');

  try {
    const composioSkills = await scrapeComposioSkills();
    allSkills.push(...composioSkills);
  } catch (err) {
    console.error('Error scraping Composio:', err);
  }

  console.log('');

  try {
    const openhandsSkills = await scrapeOpenHandsSkills();
    allSkills.push(...openhandsSkills);
  } catch (err) {
    console.error('Error scraping OpenHands:', err);
  }

  console.log('');

  try {
    const awesomeLlmSkills = await scrapeAwesomeLLMSkills();
    allSkills.push(...awesomeLlmSkills);
  } catch (err) {
    console.error('Error scraping Awesome LLM Skills:', err);
  }

  console.log('');

  try {
    const antigravitySkills = await scrapeAntigravitySkills();
    allSkills.push(...antigravitySkills);
  } catch (err) {
    console.error('Error scraping Antigravity Skills:', err);
  }

  console.log('\n' + '='.repeat(50));
  console.log(`\n📊 Total skills collected: ${allSkills.length}`);

  // Process and organize data, passing existing skills to preserve scrapedAt dates
  const processedData = processSkills(allSkills, existingSkills, stars);
  const searchIndex = generateSearchIndex(processedData.skills);

  // Ensure output directory exists
  mkdirSync(OUTPUT_DIR, { recursive: true });

  // Write main data file
  const dataPath = join(OUTPUT_DIR, 'skills.json');
  writeFileSync(dataPath, JSON.stringify(processedData, null, 2));
  console.log(`\n✅ Wrote skills data to ${dataPath}`);

  // Write search index
  const indexPath = join(OUTPUT_DIR, 'search-index.json');
  writeFileSync(indexPath, JSON.stringify(searchIndex, null, 2));
  console.log(`✅ Wrote search index to ${indexPath}`);

  // Write individual skill files for detail pages
  const skillsDir = join(OUTPUT_DIR, 'skills');
  mkdirSync(skillsDir, { recursive: true });

  for (const skill of processedData.skills) {
    const skillPath = join(skillsDir, `${skill.slug}.json`);
    writeFileSync(skillPath, JSON.stringify(skill, null, 2));
  }
  console.log(`✅ Wrote ${processedData.skills.length} individual skill files`);

  // Print summary
  console.log('\n📈 Summary:');
  console.log(`  - Total Skills: ${processedData.stats.totalSkills}`);
  console.log(`  - New Skills: ${processedData.stats.newSkills}`);
  console.log(`  - Categories: ${processedData.categories.length}`);
  console.log(`  - Scraped At: ${processedData.stats.scrapedAt}`);
  console.log('  - Sources:');
  for (const source of processedData.sources) {
    const newLabel = source.newSkillCount && source.newSkillCount > 0
      ? ` (${source.newSkillCount} new)`
      : '';
    const starsLabel = source.stars ? ` ⭐${source.stars.toLocaleString()}` : '';
    console.log(`    • ${source.name}: ${source.skillCount} skills${newLabel}${starsLabel}`);
  }

  console.log('\n🎉 Scraping complete!\n');
}

main().catch(console.error);
