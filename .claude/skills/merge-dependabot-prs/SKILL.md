---
name: merge-dependabot-prs
description: Analyze and merge open Dependabot pull requests with testing and user confirmation before committing
---

# Merge Dependabot PRs

Analyze and integrate open Dependabot pull requests into the codebase with proper testing and user confirmation before committing.

## Workflow

### Step 1: Discover Open PRs

List all open Dependabot pull requests:

```bash
gh pr list --state open --author "app/dependabot" --json number,title,headRefName,updatedAt
```

If no PRs are found, also check for any PRs with "dependabot" in the branch name:

```bash
gh pr list --state open --json number,title,headRefName,author
```

### Step 2: Categorize PRs

Group the PRs by type:
- **Go dependencies**: PRs updating `go.mod`/`go.sum` files
- **NPM dependencies**: PRs updating `package.json`/`package-lock.json` files
- **GitHub Actions**: PRs updating `.github/workflows/` files
- **Security updates**: PRs with "security" in the title or marked as security fixes

### Step 3: Analyze Each PR

For each PR, analyze:

1. **Check PR status and mergability**:
   ```bash
   gh pr view <PR_NUMBER> --json mergeable,mergeStateStatus,statusCheckRollup
   ```

2. **Review the changes**:
   ```bash
   gh pr diff <PR_NUMBER>
   ```

3. **Check for breaking changes**:
   - Look for major version bumps (e.g., v1.x.x to v2.x.x)
   - Check release notes for breaking changes
   - Identify if the dependency is direct or indirect

4. **Check for conflicts**:
   - If multiple PRs update the same file, they may conflict
   - Prioritize security updates and major dependency groups

### Step 4: Merge Strategy

**For mergeable PRs without conflicts:**
```bash
gh pr merge <PR_NUMBER> --merge --delete-branch
```

**For PRs with conflicts or requiring manual resolution:**
1. Pull the latest main branch
2. Manually update the dependency using appropriate package manager:
   - Go: `go get <package>@<version> && go mod tidy`
   - NPM: `npm update <package>` or edit package.json
3. Close the conflicting PR with a comment explaining the resolution

### Step 5: Run Tests

After merging or making manual changes, run the full test suite:

**Build all components:**
```bash
make build-all
```

**Run tests for each module:**
```bash
make -C k8s-scan-server test
make -C pod-scanner test
make -C k8s-update-controller test
make -C bjorn2scan-agent test
```

**For scanner-core (note: integration tests may be slow due to Grype DB):**
```bash
cd scanner-core && go test -v -short ./...
```

### Step 6: Handle Test Failures

If tests fail after dependency updates:

1. **Identify the breaking change** by reviewing:
   - Error messages
   - Changed API signatures
   - Deprecated function usage

2. **Make necessary code changes**:
   - Update API calls to match new library versions
   - Fix deprecated function usage
   - Update type definitions if needed

3. **Re-run tests** to verify fixes

### Step 7: Run Linters (If Code Changed)

If any code changes were made (not just dependency updates), run linters before committing:

**Go modules** - run golangci-lint from within each module directory:
```bash
cd k8s-scan-server && golangci-lint run ./...
cd pod-scanner && golangci-lint run ./...
cd k8s-update-controller && golangci-lint run ./...
cd bjorn2scan-agent && golangci-lint run ./...
cd scanner-core && golangci-lint run ./...
```

**NPM/Web** - run web linting:
```bash
cd scanner-core/web && npm run lint
```

Fix any linting errors before proceeding to commit.

### Step 8: Commit Changes (User Confirmation Required)

**IMPORTANT: Always ask the user before committing any changes.**

Present a summary of:
- PRs that were merged
- Manual dependency updates made
- Code changes made to accommodate updates
- Test results

Ask: "Would you like me to commit these changes?"

If approved, commit with an appropriate message:
```bash
git add <files>
git commit -m "chore(deps): <description of updates>

<Details of what was updated>

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>"
```

## Error Handling

### Common Issues

1. **PR not mergeable due to CI failures**:
   - Check the CI status: `gh pr checks <PR_NUMBER>`
   - Review failed checks and determine if they're related to the update

2. **Conflicting PRs**:
   - Merge PRs in order of importance (security first, then by age)
   - Use `@dependabot rebase` comment to rebase remaining PRs

3. **Breaking API changes**:
   - Search for usage of the updated package
   - Review the package's changelog/release notes
   - Make minimal code changes to restore compatibility

## Notes

- This skill is designed for the b2s-go monorepo structure with multiple Go modules
- The scanner-core integration tests may timeout due to Grype DB downloads - this is expected
- Always preserve the existing commit style and conventions
