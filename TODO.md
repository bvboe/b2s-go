# bjorn2scan TODO

## Active Tasks
- [ ] None currently

## In Progress
- [ ] None currently

## Backlog
- [ ] Clean up agent configuration management:
  - [ ] Make defaults.conf the single source of truth (embed in binary at compile time)
  - [ ] Move defaults from scanner-core to component-specific (agent, k8s-scan-server)
  - [ ] Ensure agent.conf.example matches actual code defaults
  - [ ] Add --show-config flag to display current configuration
- [ ] Test sorting on all tables
- [ ] Node scanning
- [x] Agent autoupdate (API already implemented: POST /api/update/trigger)
- [ ] Auto-update improvements:
  - [ ] Replace GitHub API calls with Atom feed parsing (avoids 60 req/hour rate limit)
    - Current: 3-5 API calls per update check (GetLatestRelease + 2-4 DownloadAsset)
    - Proposed: Parse https://github.com/bvboe/b2s-go/releases.atom (no rate limits)
    - Still use direct download URLs for assets (no API needed)
  - [ ] Fix release workflow to prevent incomplete releases
    - Issue: Component jobs attach assets as they complete, creating release before all assets ready
    - Current: First job to finish creates release, others update it (race condition)
    - Solution: Collect all artifacts, attach atomically in helm-release job
    - Files: .github/workflows/release.yaml, .github/workflows/go-binary-reusable.yaml
  - [ ] Add asset availability validation in updater before download attempts
- [ ] Remote workers for increased performance?
- [ ] Test bjorn2scan-agent install.sh on major Linux distributions:
  - [ ] Ubuntu 22.04/24.04 LTS
  - [ ] Debian 11/12
  - [ ] Alpine Linux (BusyBox compatibility)
  - [ ] Amazon Linux 2/2023
  - [ ] RHEL/Rocky/AlmaLinux 8/9
  - [ ] Fedora (latest)
  - [ ] Raspberry Pi OS (ARM64)
- [ ] OpenTelemetry integration
- [ ] Database optimization
- [ ] github.com/bvboe/b2s-go/scanner-core shows with version unknown in sbom
- [ ] Other K8s distributions
  - [ ] K3s testing
  - [ ] Microk8s testing
  - [ ] GKE
  - [ ] EKS
  - [ ] AKS
- [ ] Scheduled tasks (rescan, clean up data, delete old data)
- [ ] Delete all data in container_instances and related tables, if there are no container_instances depending on that information. (done - I think)
- [ ] Trigger rescan of all container_images whenever the database for grype is updated
- [ ] Sending data using opentelemetry to a remove opentelemetry server
- [ ] Make sure auto updates verify signatures (signature verification stub needs implementation in verifier.go)
- [ ] Fix input validation bug in github_client.go NewGitHubClient() - allow empty owner/repo parts
- [ ] Add GitHub API rate limiting handling to github_client.go
- [ ] Make checkHealth() retry interval configurable (currently hardcoded to 2 seconds)
- [ ] Implement cosign signature verification in verifier.go (currently just returns nil), also for helm and put SHAs in values.yml

## Recently Completed
- [x] [2025-12-26] Fixed GitHub Actions workflow tarball extraction bug (binary name mismatch)
- [x] [2025-12-26] Updated install.sh to work with new tarball format (generic binary name)
- [x] [2025-12-26] Researched GitHub API rate limiting and Atom feed alternative
- [x] [2025-12-26] Researched update trigger API feasibility (agent: ✅ exists, k8s: ⚠️ complex, documented in docs/)
- [x] [2025-12-26] Comprehensive test suite for bjorn2scan-agent/updater package (2,408 lines, 117 test cases)
- [x] [2025-12-26] Improved test coverage from ~20% to 46.8% for agent updater
- [x] [2025-12-26] Fixed agent Makefile to create tarballs with correct binary name (fixes extraction bug)
- [x] [2025-12-26] Added tests that would have caught the platform-specific binary name bug
- [x] [2025-12-26] Fixed all linting issues (18 errcheck and staticcheck warnings)
- [x] [2025-12-22] Created deep-scan-test script for validating syft/grype integration
- [x] [2025-12-22] Added GitHub Actions caching to all reusable workflows
- [x] [2025-12-22] Added cache monitoring/reporting to workflows
- [x] [2025-12-22] Created local workflow testing with act (.actrc + scripts/test-workflows-local)
- [x] [2025-12-22] Added hover highlighting to vulnerability and SBOM tables in image.html
- [x] [2025-12-22] Fixed Summary navigation underline on index.html

---

**Notes:**
- This file persists across Claude conversation contexts
- Claude reads this at session start to understand current work
- Tasks move from Active → In Progress → Recently Completed
- Keep Recently Completed items for ~30 days for reference
