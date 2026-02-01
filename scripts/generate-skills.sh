#!/bin/bash

# Generate SKILL.md files from JSON data for skills.sh compatibility
#
# This script creates a skills/ directory with SKILL.md files that can be
# discovered and installed via `npx skills add ranbot-ai/awesome-skills`
#
# Usage:
#   ./scripts/generate-skills.sh              # Generate from data/
#   ./scripts/generate-skills.sh --clean      # Remove generated skills
#   ./scripts/generate-skills.sh --help       # Show help
#
# Requirements:
#   - jq (for JSON parsing)

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
DATA_DIR="$ROOT_DIR/data"
SKILLS_OUTPUT_DIR="$ROOT_DIR/skills"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Logging functions
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
print_banner() {
    echo ""
    echo -e "${CYAN}${BOLD}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}${BOLD}║          Skills.sh Generator                              ║${NC}"
    echo -e "${CYAN}${BOLD}║          Generate SKILL.md files for npx skills           ║${NC}"
    echo -e "${CYAN}${BOLD}║                                                           ║${NC}"
    echo -e "${CYAN}${BOLD}║          RanBOT Labs (ranbot.online)                      ║${NC}"
    echo -e "${CYAN}${BOLD}╚═══════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# Show help
show_help() {
    print_banner
    echo -e "${BOLD}USAGE:${NC}"
    echo "  ./scripts/generate-skills.sh [OPTIONS]"
    echo ""
    echo -e "${BOLD}OPTIONS:${NC}"
    echo "  --help, -h     Show this help message"
    echo "  --clean, -c    Remove all generated skills"
    echo "  --dry-run, -n  Show what would be generated without creating files"
    echo ""
    echo -e "${BOLD}DESCRIPTION:${NC}"
    echo "  Generates SKILL.md files from JSON data for compatibility with"
    echo "  the skills.sh CLI (npx skills add ranbot-ai/awesome-skills)."
    echo ""
    echo "  Each skill gets its own directory with a SKILL.md file containing"
    echo "  YAML frontmatter and the skill content."
    echo ""
    echo -e "${BOLD}OUTPUT:${NC}"
    echo "  skills/"
    echo "  ├── skill-name/"
    echo "  │   └── SKILL.md"
    echo "  └── ..."
    echo ""
}

# Check for jq
check_requirements() {
    if ! command -v jq &> /dev/null; then
        log_error "jq is required but not installed."
        echo ""
        echo "Install jq:"
        echo "  macOS:  brew install jq"
        echo "  Ubuntu: apt install jq"
        echo "  Fedora: dnf install jq"
        echo ""
        exit 1
    fi
}

# Clean generated skills
clean_skills() {
    if [ -d "$SKILLS_OUTPUT_DIR" ]; then
        log_info "Removing $SKILLS_OUTPUT_DIR..."
        rm -rf "$SKILLS_OUTPUT_DIR"
        log_success "Cleaned generated skills"
    else
        log_info "No skills directory to clean"
    fi
}

# Escape special characters for YAML
escape_yaml() {
    local str="$1"
    # Escape quotes and newlines for YAML
    echo "$str" | sed 's/"/\\"/g' | tr '\n' ' ' | sed 's/  */ /g'
}

# Generate a single SKILL.md file
generate_skill() {
    local skill_json="$1"
    local dry_run="$2"

    local slug name description content category source tags skill_url

    slug=$(echo "$skill_json" | jq -r '.slug')
    name=$(echo "$skill_json" | jq -r '.name')
    description=$(echo "$skill_json" | jq -r '.description')
    content=$(echo "$skill_json" | jq -r '.content')
    category=$(echo "$skill_json" | jq -r '.category')
    source=$(echo "$skill_json" | jq -r '.source')
    tags=$(echo "$skill_json" | jq -r '.tags | join(", ")')
    skill_url=$(echo "$skill_json" | jq -r '.skillUrl')

    # Use slug as directory name
    local skill_dir="$SKILLS_OUTPUT_DIR/$slug"
    local skill_file="$skill_dir/SKILL.md"

    if [ "$dry_run" = "true" ]; then
        echo "  Would create: $skill_file"
        return
    fi

    # Create directory
    mkdir -p "$skill_dir"

    # Generate SKILL.md with YAML frontmatter
    cat > "$skill_file" << EOF
---
name: $name
description: $(echo "$description" | head -c 200 | tr '\n' ' ')
category: $category
source: $source
tags: [$tags]
url: $skill_url
---

$content
EOF

    return 0
}

# Generate all skills
generate_all_skills() {
    local dry_run="$1"

    if [ ! -f "$DATA_DIR/skills.json" ]; then
        log_error "skills.json not found at $DATA_DIR/skills.json"
        echo "Run the scraper first: npm run scrape"
        exit 1
    fi

    log_info "Reading skills from $DATA_DIR/skills.json..."

    local total
    total=$(jq '.skills | length' "$DATA_DIR/skills.json")

    log_info "Found $total skills to generate"
    echo ""

    if [ "$dry_run" != "true" ]; then
        # Create output directory
        mkdir -p "$SKILLS_OUTPUT_DIR"
    fi

    local count=0
    local failed=0

    # Process each skill
    while IFS= read -r skill_json; do
        count=$((count + 1))
        local slug
        slug=$(echo "$skill_json" | jq -r '.slug')

        if [ "$dry_run" != "true" ]; then
            echo -ne "\r${BLUE}[INFO]${NC} Generating $count/$total: $slug                    "
        fi

        if ! generate_skill "$skill_json" "$dry_run"; then
            failed=$((failed + 1))
        fi
    done < <(jq -c '.skills[]' "$DATA_DIR/skills.json")

    echo ""
    echo ""

    if [ "$dry_run" = "true" ]; then
        log_info "Dry run complete. Would generate $count skills."
    else
        log_success "Generated $((count - failed)) skills to $SKILLS_OUTPUT_DIR"

        if [ $failed -gt 0 ]; then
            log_warning "$failed skills failed to generate"
        fi

        echo ""
        echo -e "${CYAN}Skills are now compatible with skills.sh!${NC}"
        echo ""
        echo "Users can install with:"
        echo -e "  ${GREEN}npx skills add ranbot-ai/awesome-skills${NC}"
        echo ""
    fi
}

# Main function
main() {
    local action="generate"
    local dry_run=false

    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                show_help
                exit 0
                ;;
            --clean|-c)
                action="clean"
                shift
                ;;
            --dry-run|-n)
                dry_run=true
                shift
                ;;
            *)
                log_error "Unknown option: $1"
                echo "Use --help for usage information"
                exit 1
                ;;
        esac
    done

    print_banner
    check_requirements

    case $action in
        generate)
            generate_all_skills "$dry_run"
            ;;
        clean)
            clean_skills
            ;;
    esac
}

# Run main
main "$@"
