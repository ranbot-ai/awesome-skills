---
name: hugging-face-cli
description: Use the Hugging Face Hub CLI (`hf`) to download, upload, and manage models, datasets, and Spaces. 
category: AI & Agents
source: antigravity
tags: [python, markdown, claude, ai, gpt, image, rag]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/hugging-face-cli
---


Install by downloading the installer script first, reviewing it, and then running it locally. Example:
`tmpdir="$(mktemp -d)" && trap 'rm -rf "$tmpdir"' EXIT && curl -LsSf https://hf.co/cli/install.sh -o "$tmpdir/hf-install.sh" && less "$tmpdir/hf-install.sh" && bash "$tmpdir/hf-install.sh"`

## When to Use
Use this skill when you need the `hf` CLI for Hub authentication, downloads, uploads, repo management, or basic compute operations.

The Hugging Face Hub CLI tool `hf` is available. IMPORTANT: The `hf` command replaces the deprecated `huggingface-cli` command.

Use `hf --help` to view available functions. Note that auth commands are now all under `hf auth` e.g. `hf auth whoami`.

Generated with `huggingface_hub v1.8.0`. Run `hf skills add --force` to regenerate.

## Commands

- `hf download REPO_ID` — Download files from the Hub. `[--type CHOICE --revision TEXT --include TEXT --exclude TEXT --cache-dir TEXT --local-dir TEXT --force-download --dry-run --quiet --max-workers INTEGER]`
- `hf env` — Print information about the environment.
- `hf sync` — Sync files between local directory and a bucket. `[--delete --ignore-times --ignore-sizes --plan TEXT --apply TEXT --dry-run --include TEXT --exclude TEXT --filter-from TEXT --existing --ignore-existing --verbose --quiet]`
- `hf upload REPO_ID` — Upload a file or a folder to the Hub. Recommended for single-commit uploads. `[--type CHOICE --revision TEXT --private --include TEXT --exclude TEXT --delete TEXT --commit-message TEXT --commit-description TEXT --create-pr --every FLOAT --quiet]`
- `hf upload-large-folder REPO_ID LOCAL_PATH` — Upload a large folder to the Hub. Recommended for resumable uploads. `[--type CHOICE --revision TEXT --private --include TEXT --exclude TEXT --num-workers INTEGER --no-report --no-bars]`
- `hf version` — Print information about the hf version.

### `hf auth` — Manage authentication (login, logout, etc.).

- `hf auth list` — List all stored access tokens.
- `hf auth login` — Login using a token from huggingface.co/settings/tokens. `[--add-to-git-credential --force]`
- `hf auth logout` — Logout from a specific token. `[--token-name TEXT]`
- `hf auth switch` — Switch between access tokens. `[--token-name TEXT --add-to-git-credential]`
- `hf auth whoami` — Find out which huggingface.co account you are logged in as. `[--format CHOICE]`

### `hf buckets` — Commands to interact with buckets.

- `hf buckets cp SRC` — Copy a single file to or from a bucket. `[--quiet]`
- `hf buckets create BUCKET_ID` — Create a new bucket. `[--private --exist-ok --quiet]`
- `hf buckets delete BUCKET_ID` — Delete a bucket. `[--yes --missing-ok --quiet]`
- `hf buckets info BUCKET_ID` — Get info about a bucket. `[--quiet]`
- `hf buckets list` — List buckets or files in a bucket. `[--human-readable --tree --recursive --format CHOICE --quiet]`
- `hf buckets move FROM_ID TO_ID` — Move (rename) a bucket to a new name or namespace.
- `hf buckets remove ARGUMENT` — Remove files from a bucket. `[--recursive --yes --dry-run --include TEXT --exclude TEXT --quiet]`
- `hf buckets sync` — Sync files between local directory and a bucket. `[--delete --ignore-times --ignore-sizes --plan TEXT --apply TEXT --dry-run --include TEXT --exclude TEXT --filter-from TEXT --existing --ignore-existing --verbose --quiet]`

### `hf cache` — Manage local cache directory.

- `hf cache list` — List cached repositories or revisions. `[--cache-dir TEXT --revisions --filter TEXT --format CHOICE --quiet --sort CHOICE --limit INTEGER]`
- `hf cache prune` — Remove detached revisions from the cache. `[--cache-dir TEXT --yes --dry-run]`
- `hf cache rm TARGETS` — Remove cached repositories or revisions. `[--cache-dir TEXT --yes --dry-run]`
- `hf cache verify REPO_ID` — Verify checksums for a single repo revision from cache or a local directory. `[--type CHOICE --revision TEXT --cache-dir TEXT --local-dir TEXT --fail-on-missing-files --fail-on-extra-files]`

### `hf collections` — Interact with collections on the Hub.

- `hf collections add-item COLLECTION_SLUG ITEM_ID ITEM_TYPE` — Add an item to a collection. `[--note TEXT --exists-ok]`
- `hf collections create TITLE` — Create a new collection on the Hub. `[--namespace TEXT --description TEXT --private --exists-ok]`
- `hf collections delete COLLECTION_SLUG` — Delete a collection from the Hub. `[--missing-ok]`
- `hf collections delete-item COLLECTION_SLUG ITEM_OBJECT_ID` — Delete an item from a collection. `[--missing-ok]`
- `hf collections info COLLECTION_SLUG` — Get info about a collection on the Hub. Output is in JSON format.
- `hf collections list` — List collections on the Hub. `[--owner TEXT --item TEXT --sort CHOICE --limit INTEGER --format CHOICE --quiet]`
- `hf collections update COLLECTION_SLUG` — Update a collection's metadata on the Hub. `[--title TEXT --description TEXT --position INTEGER --private --theme TEXT]`
- `hf collections update-item COLLECTION_SLUG ITEM_OBJECT_ID` — Update an item in a collection. `[--note TEXT --position I
