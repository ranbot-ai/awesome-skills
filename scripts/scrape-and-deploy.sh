#!/bin/bash

# Agent Skills Scraper - Automated Scrape & Deploy Script
# This script scrapes all skill repositories and pushes updates to the remote repo

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
DATA_DIR="$PROJECT_ROOT/data"
WEB_PUBLIC_DIR="$PROJECT_ROOT/web/public/data"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Print banner
echo ""
echo "=========================================="
echo "  Agent Skills - Scrape & Deploy"
echo "  RanBOT Labs (ranbot.online)"
echo "=========================================="
echo ""

# Change to project root
cd "$PROJECT_ROOT"

# Step 1: Install dependencies if needed
log_info "Checking dependencies..."
if [ ! -d "$PROJECT_ROOT/scraper/node_modules" ]; then
    log_info "Installing scraper dependencies..."
    cd "$PROJECT_ROOT/scraper" && npm install
    cd "$PROJECT_ROOT"
fi

# Step 2: Build the scraper
log_info "Building scraper..."
cd "$PROJECT_ROOT/scraper"
npm run build
cd "$PROJECT_ROOT"
log_success "Scraper built successfully"

# Step 3: Run the scraper
log_info "Running scraper to fetch skills from all repositories..."
cd "$PROJECT_ROOT/scraper"
npm run scrape
cd "$PROJECT_ROOT"
log_success "Scraping completed"

# Step 4: Copy data to web public directory
log_info "Copying data to web public directory..."
mkdir -p "$WEB_PUBLIC_DIR/skills"
cp "$DATA_DIR/skills.json" "$WEB_PUBLIC_DIR/skills.json"
cp "$DATA_DIR/search-index.json" "$WEB_PUBLIC_DIR/search-index.json"
cp -r "$DATA_DIR/skills/"* "$WEB_PUBLIC_DIR/skills/"
log_success "Data copied to web public directory"

# Step 5: Get statistics
TOTAL_SKILLS=$(cat "$DATA_DIR/skills.json" | grep -o '"id"' | wc -l | tr -d ' ')
log_info "Total skills scraped: $TOTAL_SKILLS"

# Step 6: Git operations (if --push flag is provided)
if [[ "$1" == "--push" ]] || [[ "$1" == "-p" ]]; then
    log_info "Preparing to push changes to remote repository..."

    # Check if there are changes
    if git diff --quiet && git diff --staged --quiet; then
        log_warning "No changes to commit"
    else
        # Get current timestamp
        TIMESTAMP=$(date -u +"%Y-%m-%d %H:%M:%S UTC")

        # Stage changes
        git add "$DATA_DIR/"
        git add "$WEB_PUBLIC_DIR/"

        # Create commit
        COMMIT_MSG="chore: update skills data - $TIMESTAMP

Automated scrape:
- Total skills: $TOTAL_SKILLS
- Scraped at: $TIMESTAMP"

        git commit -m "$COMMIT_MSG"
        log_success "Changes committed"

        # Push to remote
        log_info "Pushing to remote repository..."
        git push
        log_success "Changes pushed to remote"
    fi
else
    log_info "Skipping git push (use --push or -p flag to push changes)"
fi

# Step 7: Build web app (if --build flag is provided)
if [[ "$1" == "--build" ]] || [[ "$2" == "--build" ]] || [[ "$1" == "-b" ]] || [[ "$2" == "-b" ]]; then
    log_info "Building web application..."
    cd "$PROJECT_ROOT/web"
    npm run build
    cd "$PROJECT_ROOT"
    log_success "Web application built successfully"
fi

echo ""
echo "=========================================="
log_success "Scrape & Deploy completed!"
echo "=========================================="
echo ""
