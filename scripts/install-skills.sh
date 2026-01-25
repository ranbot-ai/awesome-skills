#!/bin/bash

# Agent Skills Installer - Download and setup skills in ~/.claude/skills
#
# Usage:
#   ./install-skills.sh              # Install all skills
#   ./install-skills.sh --list       # List available skills
#   ./install-skills.sh skill-name   # Install specific skill(s)
#   ./install-skills.sh --help       # Show help
#
# One-liner (from anywhere):
#   curl -fsSL https://raw.githubusercontent.com/ranbot-ai/awesome-skills/main/scripts/install-skills.sh | bash
#   curl -fsSL https://raw.githubusercontent.com/ranbot-ai/awesome-skills/main/scripts/install-skills.sh | bash -s -- skill-name

set -e

# Configuration
SKILLS_DIR="${CLAUDE_SKILLS_DIR:-$HOME/.claude/skills}"
REPO_URL="https://raw.githubusercontent.com/ranbot-ai/awesome-skills/main"
DATA_URL="$REPO_URL/data"
LOCAL_DATA_DIR=""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

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
    echo -e "${CYAN}${BOLD}║          Agent Skills Installer                           ║${NC}"
    echo -e "${CYAN}${BOLD}║          Install skills to ~/.claude/skills               ║${NC}"
    echo -e "${CYAN}${BOLD}║                                                           ║${NC}"
    echo -e "${CYAN}${BOLD}║          RanBOT Labs (ranbot.online)                      ║${NC}"
    echo -e "${CYAN}${BOLD}╚═══════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# Show help
show_help() {
    print_banner
    echo -e "${BOLD}USAGE:${NC}"
    echo "  ./install-skills.sh [OPTIONS] [SKILL_NAMES...]"
    echo ""
    echo -e "${BOLD}OPTIONS:${NC}"
    echo "  --help, -h          Show this help message"
    echo "  --list, -l          List all available skills"
    echo "  --all, -a           Install all skills (default if no args)"
    echo "  --local, -L PATH    Use local data directory instead of remote"
    echo "  --update, -u        Update existing skills (overwrite)"
    echo "  --category, -c CAT  Install all skills in a category"
    echo "  --source, -s SRC    Install all skills from a source"
    echo "  --search, -S TERM   Search skills by name/description"
    echo "  --info, -i SKILL    Show detailed info about a skill"
    echo "  --uninstall SKILL   Remove a skill from ~/.claude/skills"
    echo "  --clean             Remove all installed skills"
    echo ""
    echo -e "${BOLD}EXAMPLES:${NC}"
    echo "  # Install all skills"
    echo "  ./install-skills.sh"
    echo ""
    echo "  # Install specific skills"
    echo "  ./install-skills.sh code-review docker kubernetes"
    echo ""
    echo "  # Install from local data directory"
    echo "  ./install-skills.sh --local ./data"
    echo ""
    echo "  # List available skills"
    echo "  ./install-skills.sh --list"
    echo ""
    echo "  # Search for skills"
    echo "  ./install-skills.sh --search docker"
    echo ""
    echo "  # Install all skills from a source"
    echo "  ./install-skills.sh --source anthropic"
    echo ""
    echo "  # One-liner installation (from anywhere)"
    echo "  curl -fsSL $REPO_URL/scripts/install-skills.sh | bash"
    echo "  curl -fsSL $REPO_URL/scripts/install-skills.sh | bash -s -- code-review"
    echo ""
    echo -e "${BOLD}ENVIRONMENT VARIABLES:${NC}"
    echo "  CLAUDE_SKILLS_DIR   Override skills directory (default: ~/.claude/skills)"
    echo ""
    echo -e "${BOLD}SKILLS DIRECTORY:${NC}"
    echo "  $SKILLS_DIR"
    echo ""
}

# Check for required tools
check_requirements() {
    local missing=()

    if ! command -v curl &> /dev/null; then
        missing+=("curl")
    fi

    if ! command -v jq &> /dev/null; then
        # jq is optional but recommended
        log_warning "jq not found. Using basic JSON parsing (install jq for better experience)"
        USE_JQ=false
    else
        USE_JQ=true
    fi

    if [ ${#missing[@]} -ne 0 ]; then
        log_error "Missing required tools: ${missing[*]}"
        echo "Please install them and try again."
        exit 1
    fi
}

# Fetch skills.json (from remote or local)
fetch_skills_json() {
    if [ -n "$LOCAL_DATA_DIR" ]; then
        if [ -f "$LOCAL_DATA_DIR/skills.json" ]; then
            cat "$LOCAL_DATA_DIR/skills.json"
        else
            log_error "Local skills.json not found at $LOCAL_DATA_DIR/skills.json"
            exit 1
        fi
    else
        curl -fsSL "$DATA_URL/skills.json" 2>/dev/null || {
            log_error "Failed to fetch skills data from $DATA_URL/skills.json"
            exit 1
        }
    fi
}

# Fetch individual skill JSON
fetch_skill_json() {
    local slug="$1"

    if [ -n "$LOCAL_DATA_DIR" ]; then
        if [ -f "$LOCAL_DATA_DIR/skills/$slug.json" ]; then
            cat "$LOCAL_DATA_DIR/skills/$slug.json"
        else
            log_error "Local skill not found: $LOCAL_DATA_DIR/skills/$slug.json"
            return 1
        fi
    else
        curl -fsSL "$DATA_URL/skills/$slug.json" 2>/dev/null || {
            log_error "Failed to fetch skill: $slug"
            return 1
        }
    fi
}

# Parse JSON with jq or basic parsing
json_get() {
    local json="$1"
    local key="$2"

    if $USE_JQ; then
        echo "$json" | jq -r "$key" 2>/dev/null
    else
        # Basic parsing for simple keys (fallback)
        echo "$json" | grep -o "\"$key\": *\"[^\"]*\"" | sed 's/.*: *"\([^"]*\)"/\1/' | head -1
    fi
}

# Get array of skills
get_skills_array() {
    local json="$1"

    if $USE_JQ; then
        echo "$json" | jq -r '.skills[]'
    else
        # Fallback - less reliable
        echo "$json"
    fi
}

# List all available skills
list_skills() {
    log_info "Fetching available skills..."

    local skills_json
    skills_json=$(fetch_skills_json)

    if $USE_JQ; then
        local total
        total=$(echo "$skills_json" | jq '.skills | length')

        echo ""
        echo -e "${BOLD}Available Skills ($total total):${NC}"
        echo ""

        # Group by source
        local sources
        sources=$(echo "$skills_json" | jq -r '.skills[].source' | sort | uniq)

        for source in $sources; do
            local source_skills
            source_skills=$(echo "$skills_json" | jq -r ".skills[] | select(.source == \"$source\") | \"  \\(.slug)\"" | sort)
            local count
            count=$(echo "$source_skills" | wc -l | tr -d ' ')

            echo -e "${CYAN}${BOLD}[$source]${NC} ($count skills)"
            echo "$source_skills"
            echo ""
        done
    else
        # Basic listing without jq
        echo ""
        echo -e "${BOLD}Available Skills:${NC}"
        echo "(Install jq for better formatting)"
        echo ""
        echo "$skills_json" | grep -o '"slug": *"[^"]*"' | sed 's/"slug": *"\([^"]*\)"/  \1/' | sort
    fi
}

# Search skills
search_skills() {
    local term="$1"

    log_info "Searching for: $term"

    local skills_json
    skills_json=$(fetch_skills_json)

    if $USE_JQ; then
        local results
        results=$(echo "$skills_json" | jq -r ".skills[] | select(.name + .description + .slug | test(\"$term\"; \"i\")) | \"  \\(.slug) - \\(.name)\"")

        if [ -z "$results" ]; then
            log_warning "No skills found matching: $term"
        else
            echo ""
            echo -e "${BOLD}Search Results:${NC}"
            echo "$results"
            echo ""
        fi
    else
        log_warning "Search requires jq to be installed"
        exit 1
    fi
}

# Show skill info
show_skill_info() {
    local slug="$1"

    log_info "Fetching info for: $slug"

    local skill_json
    skill_json=$(fetch_skill_json "$slug") || exit 1

    if $USE_JQ; then
        echo ""
        echo -e "${BOLD}$(echo "$skill_json" | jq -r '.name')${NC}"
        echo ""
        echo -e "${CYAN}Slug:${NC}        $(echo "$skill_json" | jq -r '.slug')"
        echo -e "${CYAN}Source:${NC}      $(echo "$skill_json" | jq -r '.source')"
        echo -e "${CYAN}Category:${NC}    $(echo "$skill_json" | jq -r '.category')"
        echo -e "${CYAN}Repo:${NC}        $(echo "$skill_json" | jq -r '.repoUrl')"
        echo -e "${CYAN}Skill URL:${NC}   $(echo "$skill_json" | jq -r '.skillUrl')"
        echo ""
        echo -e "${CYAN}Description:${NC}"
        echo "$(echo "$skill_json" | jq -r '.description')" | fold -s -w 70
        echo ""
        echo -e "${CYAN}Tags:${NC}        $(echo "$skill_json" | jq -r '.tags | join(", ")')"
        echo ""
    else
        log_warning "Detailed info requires jq to be installed"
        echo ""
        echo "Skill: $slug"
        echo ""
    fi
}

# Convert skill JSON to markdown with frontmatter
skill_to_markdown() {
    local skill_json="$1"

    if $USE_JQ; then
        local name description category source tags content
        name=$(echo "$skill_json" | jq -r '.name')
        description=$(echo "$skill_json" | jq -r '.description')
        category=$(echo "$skill_json" | jq -r '.category')
        source=$(echo "$skill_json" | jq -r '.source')
        tags=$(echo "$skill_json" | jq -r '.tags | join(", ")')
        content=$(echo "$skill_json" | jq -r '.content')
        skill_url=$(echo "$skill_json" | jq -r '.skillUrl')

        cat << EOF
---
name: $name
description: $description
category: $category
source: $source
tags: [$tags]
url: $skill_url
---

$content
EOF
    else
        # Basic conversion without jq
        local content
        content=$(echo "$skill_json" | grep -o '"content": *"[^"]*"' | sed 's/"content": *"\([^"]*\)"/\1/' | sed 's/\\n/\n/g')
        echo "$content"
    fi
}

# Install a single skill
install_skill() {
    local slug="$1"
    local force="${2:-false}"

    local target_dir="$SKILLS_DIR/$slug"
    local target_file="$target_dir/SKILL.md"

    # Check if already installed
    if [ -d "$target_dir" ] && [ "$force" != "true" ]; then
        log_warning "Skill '$slug' already installed. Use --update to overwrite."
        return 0
    fi

    # Fetch skill data
    local skill_json
    skill_json=$(fetch_skill_json "$slug") || return 1

    # Convert to markdown
    local markdown
    markdown=$(skill_to_markdown "$skill_json")

    # Create skill directory structure
    mkdir -p "$target_dir"

    # Write SKILL.md file
    echo "$markdown" > "$target_file"

    # Create optional subdirectories (empty, for user to add files)
    # mkdir -p "$target_dir/scripts"
    # mkdir -p "$target_dir/references"

    log_success "Installed: $slug"
}

# Install all skills
install_all_skills() {
    local force="${1:-false}"

    log_info "Installing all skills to $SKILLS_DIR..."

    local skills_json
    skills_json=$(fetch_skills_json)

    if $USE_JQ; then
        local slugs
        slugs=$(echo "$skills_json" | jq -r '.skills[].slug')
        local total
        total=$(echo "$slugs" | wc -l | tr -d ' ')
        local count=0

        for slug in $slugs; do
            count=$((count + 1))
            echo -ne "\r${BLUE}[INFO]${NC} Installing skill $count/$total: $slug          "
            install_skill "$slug" "$force" 2>/dev/null || true
        done

        echo ""
        log_success "Installed $count skills to $SKILLS_DIR"
    else
        log_error "Installing all skills requires jq"
        exit 1
    fi
}

# Install skills by source
install_by_source() {
    local source="$1"
    local force="${2:-false}"

    log_info "Installing skills from source: $source"

    local skills_json
    skills_json=$(fetch_skills_json)

    if $USE_JQ; then
        local slugs
        slugs=$(echo "$skills_json" | jq -r ".skills[] | select(.source == \"$source\") | .slug")

        if [ -z "$slugs" ]; then
            log_error "No skills found for source: $source"
            echo ""
            echo "Available sources:"
            echo "$skills_json" | jq -r '.skills[].source' | sort | uniq | sed 's/^/  /'
            exit 1
        fi

        local count=0
        for slug in $slugs; do
            install_skill "$slug" "$force" || true
            count=$((count + 1))
        done

        log_success "Installed $count skills from $source"
    else
        log_error "Installing by source requires jq"
        exit 1
    fi
}

# Install skills by category
install_by_category() {
    local category="$1"
    local force="${2:-false}"

    log_info "Installing skills from category: $category"

    local skills_json
    skills_json=$(fetch_skills_json)

    if $USE_JQ; then
        local slugs
        slugs=$(echo "$skills_json" | jq -r ".skills[] | select(.category | test(\"$category\"; \"i\")) | .slug")

        if [ -z "$slugs" ]; then
            log_error "No skills found for category: $category"
            echo ""
            echo "Available categories:"
            echo "$skills_json" | jq -r '.skills[].category' | sort | uniq | sed 's/^/  /'
            exit 1
        fi

        local count=0
        for slug in $slugs; do
            install_skill "$slug" "$force" || true
            count=$((count + 1))
        done

        log_success "Installed $count skills from category matching '$category'"
    else
        log_error "Installing by category requires jq"
        exit 1
    fi
}

# Uninstall a skill
uninstall_skill() {
    local slug="$1"
    local target_dir="$SKILLS_DIR/$slug"

    if [ -d "$target_dir" ]; then
        rm -rf "$target_dir"
        log_success "Uninstalled: $slug"
    elif [ -f "$SKILLS_DIR/$slug.md" ]; then
        # Backward compatibility: remove old-style .md file
        rm "$SKILLS_DIR/$slug.md"
        log_success "Uninstalled: $slug (legacy format)"
    else
        log_warning "Skill not installed: $slug"
    fi
}

# Clean all skills
clean_skills() {
    log_warning "This will remove all skills from $SKILLS_DIR"
    echo -n "Are you sure? [y/N] "
    read -r confirm

    if [ "$confirm" = "y" ] || [ "$confirm" = "Y" ]; then
        # Remove skill directories (new format)
        find "$SKILLS_DIR" -mindepth 1 -maxdepth 1 -type d -exec rm -rf {} \; 2>/dev/null || true
        # Remove legacy .md files (old format)
        rm -f "$SKILLS_DIR"/*.md 2>/dev/null || true
        log_success "All skills removed"
    else
        log_info "Cancelled"
    fi
}

# Main function
main() {
    # Parse arguments
    local action="install_all"
    local force=false
    local skills_to_install=()

    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                show_help
                exit 0
                ;;
            --list|-l)
                action="list"
                shift
                ;;
            --all|-a)
                action="install_all"
                shift
                ;;
            --local|-L)
                LOCAL_DATA_DIR="$2"
                shift 2
                ;;
            --update|-u)
                force=true
                shift
                ;;
            --category|-c)
                action="install_category"
                CATEGORY="$2"
                shift 2
                ;;
            --source|-s)
                action="install_source"
                SOURCE="$2"
                shift 2
                ;;
            --search|-S)
                action="search"
                SEARCH_TERM="$2"
                shift 2
                ;;
            --info|-i)
                action="info"
                INFO_SKILL="$2"
                shift 2
                ;;
            --uninstall)
                action="uninstall"
                UNINSTALL_SKILL="$2"
                shift 2
                ;;
            --clean)
                action="clean"
                shift
                ;;
            -*)
                log_error "Unknown option: $1"
                echo "Use --help for usage information"
                exit 1
                ;;
            *)
                skills_to_install+=("$1")
                action="install_specific"
                shift
                ;;
        esac
    done

    # Check requirements
    check_requirements

    # Ensure skills directory exists
    mkdir -p "$SKILLS_DIR"

    # Execute action
    case $action in
        list)
            print_banner
            list_skills
            ;;
        search)
            print_banner
            search_skills "$SEARCH_TERM"
            ;;
        info)
            print_banner
            show_skill_info "$INFO_SKILL"
            ;;
        install_all)
            print_banner
            install_all_skills "$force"
            ;;
        install_specific)
            print_banner
            for slug in "${skills_to_install[@]}"; do
                install_skill "$slug" "$force"
            done
            ;;
        install_source)
            print_banner
            install_by_source "$SOURCE" "$force"
            ;;
        install_category)
            print_banner
            install_by_category "$CATEGORY" "$force"
            ;;
        uninstall)
            print_banner
            uninstall_skill "$UNINSTALL_SKILL"
            ;;
        clean)
            print_banner
            clean_skills
            ;;
    esac

    echo ""
    echo -e "${CYAN}Skills directory: $SKILLS_DIR${NC}"
    echo ""
}

# Run main
main "$@"
