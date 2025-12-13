#!/usr/bin/env bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Usage
usage() {
    cat << EOF
Usage: $0 <version>

Create a new release of bjorn2scan v2 by creating and pushing a git tag.

Arguments:
  version         Version number (e.g., 0.1.0, 1.0.0)
                  DO NOT include 'v' prefix - it will be added automatically

Examples:
  $0 0.1.0              # Creates v0.1.0 release
  $0 1.0.0              # Creates v1.0.0 release

The script will:
  1. Validate the version format
  2. Check git status (must be on main, clean working tree)
  3. Check if tag already exists
  4. Create a GPG-signed git tag
  5. Push the tag to trigger the release workflow
  6. Monitor the GitHub Actions workflow
  7. Show the release URL when complete

EOF
    exit 1
}

# Validate version format
validate_version() {
    local version=$1

    log_info "Validating version: $version"

    # Check if version is empty
    if [ -z "$version" ]; then
        log_error "Version cannot be empty"
        exit 1
    fi

    # Check if version starts with 'v'
    if [[ $version =~ ^v+ ]]; then
        log_error "Version MUST NOT include 'v' prefix: $version"
        log_error "The script automatically adds 'v' prefix"
        log_info "❌ WRONG: $0 $version"
        log_info "✅ CORRECT: $0 ${version#v}"
        exit 1
    fi

    # Check if version follows semver format
    if ! [[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.-]+)?$ ]]; then
        log_error "Invalid version format: $version"
        log_info "Expected format: X.Y.Z or X.Y.Z-suffix"
        log_info "Examples:"
        log_info "  ✅ 0.1.0"
        log_info "  ✅ 1.0.0"
        log_info "  ✅ 2.0.0-rc1"
        log_info "  ✅ 1.0.0-beta.1"
        log_info "  ❌ v1.0.0    (no 'v' prefix)"
        log_info "  ❌ 1.0       (must be X.Y.Z)"
        log_info "  ❌ 1.0.0.0   (only 3 components)"
        exit 1
    fi

    log_success "Version format is valid: $version"
}

# Check git status
check_git_status() {
    log_info "Checking git status..."

    # Check if in git repository
    if ! git rev-parse --git-dir > /dev/null 2>&1; then
        log_error "Not in a git repository"
        exit 1
    fi

    # Check current branch
    local current_branch=$(git rev-parse --abbrev-ref HEAD)
    if [ "$current_branch" != "main" ]; then
        log_error "Not on main branch (currently on: $current_branch)"
        log_info "Run: git checkout main"
        exit 1
    fi
    log_success "On main branch"

    # Check if working tree is clean
    if ! git diff-index --quiet HEAD --; then
        log_error "Working tree has uncommitted changes"
        log_info "Run: git status"
        log_info "Commit or stash your changes before creating a release"
        exit 1
    fi
    log_success "Working tree is clean"

    # Check if we're up to date with remote
    log_info "Fetching latest changes from origin..."
    git fetch origin main --tags

    local local_commit=$(git rev-parse HEAD)
    local remote_commit=$(git rev-parse origin/main)

    if [ "$local_commit" != "$remote_commit" ]; then
        log_warning "Local main is not up to date with origin/main"
        read -p "Pull latest changes? [y/N] " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            git pull origin main
            log_success "Pulled latest changes"
        else
            log_error "Aborted by user"
            exit 1
        fi
    else
        log_success "Local main is up to date with origin/main"
    fi
}

# Check if tag already exists
check_existing_tag() {
    local version=$1
    local tag="v$version"

    log_info "Checking if tag $tag already exists..."

    if git rev-parse "$tag" >/dev/null 2>&1; then
        log_error "Tag $tag already exists locally"
        log_info "To delete locally: git tag -d $tag"
        exit 1
    fi

    if git ls-remote --tags origin | grep -q "refs/tags/$tag"; then
        log_error "Tag $tag already exists on remote"
        log_info "To view release: gh release view $tag"
        log_info "To delete: gh release delete $tag --yes && git push origin :refs/tags/$tag"
        exit 1
    fi

    log_success "Tag $tag does not exist"
}

# Check if gh CLI is installed
check_gh_cli() {
    if ! command -v gh &> /dev/null; then
        log_warning "GitHub CLI (gh) is not installed"
        log_info "Workflow monitoring will be skipped"
        log_info "Install with: brew install gh"
        return 1
    fi
    return 0
}

# Create and push tag
create_and_push_tag() {
    local version=$1
    local tag="v$version"

    log_info "Creating GPG-signed tag: $tag"

    if git tag -s "$tag" -m "Release $tag"; then
        log_success "Tag $tag created"
    else
        log_error "Failed to create tag"
        log_info "Make sure GPG is configured: git config --get user.signingkey"
        exit 1
    fi

    log_info "Pushing tag to origin..."
    if git push origin "$tag"; then
        log_success "Tag pushed to origin"
    else
        log_error "Failed to push tag"
        log_info "Tag was created locally. To delete: git tag -d $tag"
        exit 1
    fi
}

# Monitor workflow execution
monitor_workflow() {
    local version=$1
    local tag="v$version"

    if ! check_gh_cli; then
        log_info "Skipping workflow monitoring"
        log_info "Check status at: https://github.com/$(git config --get remote.origin.url | sed 's/.*github.com[:/]\(.*\)\.git/\1/')/actions"
        return 0
    fi

    log_info "Waiting for workflow to start (this may take a few seconds)..."
    sleep 5

    # Get the latest release workflow run
    local run_id=$(gh run list --workflow=release.yaml --limit 1 --json databaseId --jq '.[0].databaseId' 2>/dev/null)

    if [ -z "$run_id" ]; then
        log_warning "Could not find workflow run"
        log_info "Check GitHub Actions manually"
        return 0
    fi

    log_info "Release workflow started (Run ID: $run_id)"
    log_info "Watch at: https://github.com/$(gh repo view --json nameWithOwner -q .nameWithOwner)/actions/runs/$run_id"

    # Watch the workflow
    log_info "Watching workflow (integration tests + build may take 15-20 minutes)..."
    if gh run watch "$run_id" --exit-status; then
        log_success "Release workflow completed successfully!"
        return 0
    else
        log_error "Release workflow failed!"
        log_info "View logs: gh run view $run_id --log-failed"
        return 1
    fi
}

# Show release summary
show_summary() {
    local version=$1
    local tag="v$version"

    echo ""
    echo "======================================"
    echo "Release Summary"
    echo "======================================"
    log_success "Release $tag created successfully!"
    echo ""

    if check_gh_cli; then
        local repo_url="https://github.com/$(gh repo view --json nameWithOwner -q .nameWithOwner)"

        echo "📦 Release:"
        echo "  $repo_url/releases/tag/$tag"
        echo ""
        echo "🐳 Container Images:"
        echo "  ghcr.io/$(gh repo view --json nameWithOwner -q .nameWithOwner | tr '[:upper:]' '[:lower:]')/k8s-scan-server:$version"
        echo "  ghcr.io/$(gh repo view --json nameWithOwner -q .nameWithOwner | tr '[:upper:]' '[:lower:]')/k8s-scan-server:latest"
        echo ""
        echo "📦 Helm Chart (OCI):"
        echo "  oci://ghcr.io/$(gh repo view --json nameWithOwner -q .nameWithOwner | tr '[:upper:]' '[:lower:]')/bjorn2scan:$version"
        echo ""
        echo "⎈ Install with Helm (Recommended - from OCI registry):"
        echo "  helm install bjorn2scan oci://ghcr.io/$(gh repo view --json nameWithOwner -q .nameWithOwner | tr '[:upper:]' '[:lower:]')/bjorn2scan \\"
        echo "    --version $version \\"
        echo "    --namespace bjorn2scan \\"
        echo "    --create-namespace"
        echo ""
        echo "⎈ Or install from downloaded chart:"
        echo "  # Download bjorn2scan-$version.tgz from the release page"
        echo "  helm install bjorn2scan ./bjorn2scan-$version.tgz \\"
        echo "    --namespace bjorn2scan \\"
        echo "    --create-namespace"
    else
        echo "Release URL: https://github.com/<owner>/<repo>/releases/tag/$tag"
    fi

    echo ""
    echo "======================================"
}

# Main script
main() {
    # Check arguments
    if [ $# -lt 1 ]; then
        usage
    fi

    local version=$1

    echo "======================================"
    echo "bjorn2scan v2 Release Script"
    echo "======================================"
    echo ""

    # Run validations
    validate_version "$version"
    check_git_status
    check_existing_tag "$version"

    # Show what will happen
    echo ""
    echo "======================================"
    log_warning "RELEASE CONFIRMATION"
    echo "======================================"
    log_info "This will create release: v$version"
    echo ""
    log_info "The release workflow will:"
    log_info "  1. Run integration tests on kind and minikube (~10 min)"
    log_info "  2. Build and push multi-arch Docker images (amd64, arm64)"
    log_info "  3. Sign container images with cosign"
    log_info "  4. Generate and attach SBOM"
    log_info "  5. Package and attach Helm chart"
    log_info "  6. Scan images with Grype"
    log_info "  7. Create GitHub release v$version"
    echo ""
    read -p "Continue? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_error "Aborted by user"
        exit 1
    fi

    # Create release
    create_and_push_tag "$version"

    # Monitor workflow (optional if gh CLI is available)
    if monitor_workflow "$version"; then
        # Wait a moment for release to be created
        sleep 5
        show_summary "$version"
        exit 0
    else
        log_error "Release workflow failed, but tag was pushed"
        log_info "Tag $version exists and triggered the workflow"
        log_info "Check GitHub Actions for details"
        exit 1
    fi
}

# Run main
main "$@"
