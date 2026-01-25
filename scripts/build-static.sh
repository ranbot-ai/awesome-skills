#!/bin/bash

# Agent Skills - Static Build & Upload Script
# RanBOT Labs (https://ranbot.online)
#
# Usage:
#   ./scripts/build-static.sh                           # Just build static files
#   ./scripts/build-static.sh --upload user@server:/path  # Build and upload via SCP
#   ./scripts/build-static.sh --rsync user@server:/path   # Build and upload via rsync

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="$PROJECT_ROOT/web/out"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

echo ""
echo "=========================================="
echo "  Agent Skills - Static Build"
echo "  RanBOT Labs (ranbot.online)"
echo "=========================================="
echo ""

cd "$PROJECT_ROOT"

# Step 1: Install dependencies
log_info "Installing dependencies..."
npm ci --workspace=web 2>/dev/null || npm install --workspace=web

# Step 2: Build static export
log_info "Building static files..."
cd "$PROJECT_ROOT/web"
NEXT_OUTPUT=export npm run build

log_success "Static build complete!"
log_info "Output directory: $OUTPUT_DIR"

# Count files
FILE_COUNT=$(find "$OUTPUT_DIR" -type f | wc -l | tr -d ' ')
DIR_SIZE=$(du -sh "$OUTPUT_DIR" | cut -f1)
log_info "Files: $FILE_COUNT, Size: $DIR_SIZE"

# Step 3: Upload if requested
if [[ "$1" == "--upload" ]] || [[ "$1" == "-u" ]]; then
    if [[ -z "$2" ]]; then
        log_error "Please provide destination: --upload user@server:/path"
        exit 1
    fi

    DEST="$2"
    log_info "Uploading to $DEST via SCP..."
    scp -r "$OUTPUT_DIR"/* "$DEST"
    log_success "Upload complete!"

elif [[ "$1" == "--rsync" ]] || [[ "$1" == "-r" ]]; then
    if [[ -z "$2" ]]; then
        log_error "Please provide destination: --rsync user@server:/path"
        exit 1
    fi

    DEST="$2"
    log_info "Syncing to $DEST via rsync..."
    rsync -avz --delete "$OUTPUT_DIR"/ "$DEST"
    log_success "Sync complete!"

elif [[ "$1" == "--zip" ]] || [[ "$1" == "-z" ]]; then
    ZIP_FILE="$PROJECT_ROOT/awesome-skills-static.zip"
    log_info "Creating ZIP archive..."
    cd "$OUTPUT_DIR"
    zip -r "$ZIP_FILE" .
    log_success "ZIP created: $ZIP_FILE"
    log_info "Size: $(du -sh "$ZIP_FILE" | cut -f1)"

elif [[ "$1" == "--tar" ]] || [[ "$1" == "-t" ]]; then
    TAR_FILE="$PROJECT_ROOT/awesome-skills-static.tar.gz"
    log_info "Creating TAR archive..."
    cd "$OUTPUT_DIR"
    tar -czvf "$TAR_FILE" .
    log_success "TAR created: $TAR_FILE"
    log_info "Size: $(du -sh "$TAR_FILE" | cut -f1)"
fi

echo ""
log_info "Next steps:"
echo "  1. Upload files: scp -r $OUTPUT_DIR/* user@server:/var/www/html/"
echo "  2. Or use rsync: rsync -avz $OUTPUT_DIR/ user@server:/var/www/html/"
echo "  3. Or create ZIP: ./scripts/build-static.sh --zip"
echo ""
