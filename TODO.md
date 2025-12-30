# bjorn2scan TODO List

## Active Tasks
- [ ] None currently

## In Progress
- [ ] None currently

## Backlog
- [ ] Proper agent update testing
- [ ] Pick up node tags!
- [ ] Clean up agent configuration management:
  - [ ] Make defaults.conf the single source of truth (embed in binary at compile time)
  - [ ] Move defaults from scanner-core to component-specific (agent, k8s-scan-server)
  - [ ] Ensure agent.conf.example matches actual code defaults
  - [ ] Add --show-config flag to display current configuration
- [ ] Node scanning
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
- [ ] Other K8s distributions
  - [ ] GKE
  - [ ] EKS
  - [ ] AKS
- [ ] Sending data using opentelemetry to a remote opentelemetry server
- [ ] Make sure auto updates verify signatures (signature verification stub needs implementation in verifier.go)
- [ ] Make checkHealth() retry interval configurable (currently hardcoded to 2 seconds)
- [ ] Implement cosign signature verification in verifier.go (currently just returns nil), also for helm and put SHAs in values.yml

## Recently Completed
- [x] [2025-12-29] Fixed URL filter parameter application in shared.js (namespaces, vulnStatuses, packageTypes, osNames)
- [x] [2025-12-29] Added click functionality to Container Distribution Summary table (navigates to pods.html)
- [x] [2025-12-29] Updated Namespace Summary table to navigate to pods.html
- [x] [2025-12-29] Implemented filter preservation in sidebar navigation (Images/Pods links carry current filters)
- [x] [2025-12-29] Fixed agent systemd service to work without Docker installed (removed SupplementaryGroups=docker)
- [x] [2025-12-29] Made Docker socket binding optional in agent service file (BindReadOnlyPaths=-/var/run/docker.sock)
- [x] [2025-12-29] Removed CVEs and SBOM links from sidebar navigation
- [x] [2025-12-27] Removed stale TODO items for non-existent github_client.go
- [x] [2025-12-27] Confirmed agent updater uses Atom feed (no GitHub API)
- [x] [2025-12-27] Confirmed k8s updater uses OCI registry (no GitHub API)
- [x] [2025-12-26] Refactored k8s updater to use OCI registry
- [x] [2025-12-26] Replaced GitHub API calls with Atom feed parsing in agent updater
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
