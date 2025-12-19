#!/bin/bash
set -e

# Generate intelligent release notes using Claude API
# This script analyzes commits since the last release and generates a structured summary

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() { echo -e "${BLUE}[INFO]${NC} $1" >&2; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1" >&2; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1" >&2; }

# Check if Claude CLI is installed
if ! command -v claude &> /dev/null; then
    log_error "Claude CLI is not installed"
    log_info "Install with: brew install claude-cli (or visit https://claude.ai/download)"
    exit 1
fi

# Get current tag from argument or environment
if [ -n "$1" ]; then
    CURRENT_TAG="$1"
elif [ -n "$GITHUB_REF_NAME" ]; then
    CURRENT_TAG="${GITHUB_REF_NAME}"
else
    log_error "Current tag required as argument or GITHUB_REF_NAME environment variable"
    log_info "Usage: $0 <tag>"
    exit 1
fi

log_info "Current release tag: ${CURRENT_TAG}"

# Get the previous release tag
PREVIOUS_TAG=$(git describe --tags --abbrev=0 "${CURRENT_TAG}^" 2>/dev/null || echo "")

if [ -z "$PREVIOUS_TAG" ]; then
    log_warning "No previous tag found, using all commits"
    COMMIT_RANGE="HEAD"
else
    log_info "Previous release tag: ${PREVIOUS_TAG}"
    COMMIT_RANGE="${PREVIOUS_TAG}..${CURRENT_TAG}"
fi

# Get commits since last release
log_info "Fetching commits in range: ${COMMIT_RANGE}"
COMMITS=$(git log "${COMMIT_RANGE}" --pretty=format:"%h | %s | %an | %ar" --no-merges)

if [ -z "$COMMITS" ]; then
    log_warning "No commits found in range"
    echo "No changes since last release."
    exit 0
fi

COMMIT_COUNT=$(echo "$COMMITS" | wc -l | tr -d ' ')
log_info "Found ${COMMIT_COUNT} commits to analyze"

# Get file statistics
FILES_CHANGED=$(git diff --stat "${PREVIOUS_TAG}..${CURRENT_TAG}" 2>/dev/null | tail -1 || echo "")
log_info "Changes: ${FILES_CHANGED}"

# Create prompt for Claude
read -r -d '' PROMPT << EOM || true
Analyze the following Git commits and generate a concise, well-structured release summary for version ${CURRENT_TAG}.

**Commit History:**
\`\`\`
${COMMITS}
\`\`\`

**Statistics:**
${FILES_CHANGED}

**Instructions:**
1. Group changes into categories (Features, Bug Fixes, Performance, Tests, Documentation, etc.)
2. Highlight the most significant changes first
3. Be technical but concise - this is for developers/operators
4. Mention breaking changes if any (look for keywords like "breaking", "remove", "deprecate")
5. Keep the summary under 500 words
6. Use bullet points for clarity
7. Format output in Markdown

**Output Format:**
\`\`\`markdown
## 🎯 Highlights

[2-3 most important changes in this release]

## 📋 Changes by Category

### ✨ Features
- [Feature descriptions]

### 🐛 Bug Fixes
- [Bug fix descriptions]

### ⚡ Performance
- [Performance improvements]

### 🧪 Testing
- [Test improvements]

### 📚 Documentation
- [Documentation updates]

### 🔧 Internal Changes
- [Refactoring, CI/CD, etc.]

## ⚠️ Breaking Changes
[If any, otherwise omit this section]

## 📊 Statistics
- X commits from Y contributors
- Z files changed
\`\`\`

Generate the release summary now:
EOM

log_info "Calling Claude CLI to analyze commits..."

# Call Claude CLI
SUMMARY=$(echo "$PROMPT" | claude --no-stream 2>&1)

# Check for errors
if [ $? -ne 0 ]; then
    log_error "Claude CLI error: $SUMMARY"
    exit 1
fi

if [ -z "$SUMMARY" ]; then
    log_error "Failed to get summary from Claude CLI"
    exit 1
fi

log_success "Successfully generated release summary"

# Output the summary
echo "$SUMMARY"
