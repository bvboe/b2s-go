# bjorn2scan TODO List

## Active Tasks
- [ ] None currently

## In Progress
- [ ] None currently

## Backlog
- [ ] Add host_ip tracking to metrics (requires storing Kubernetes node IP in database or querying K8s API)
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
- [X] OpenTelemetry integration
- [X] Database optimization
- [ ] Other K8s distributions
  - [ ] GKE
  - [ ] EKS
  - [ ] AKS
- [X] Sending data using opentelemetry to a remote opentelemetry server
- [ ] Make sure auto updates verify signatures (signature verification stub needs implementation in verifier.go)
- [ ] Make checkHealth() retry interval configurable (currently hardcoded to 2 seconds)
- [ ] Implement cosign signature verification in verifier.go (currently just returns nil), also for helm and put SHAs in values.yml

## Recently Completed
- [X] [2025-12-30] Implemented Prometheus metrics endpoint at /metrics
  - Created scanner-core/metrics package with lightweight Prometheus text format generator
  - Exposed metrics: scanned_instances, vulnerabilities_total, packages_total, scan_status, images_total, instances_total
  - Metrics include rich labels: cluster_name, namespace, pod_name, container_name, image, image_id, distro_name, severity, etc.
  - Registered /metrics endpoint in both bjorn2scan-agent and k8s-scan-server
  - Added database query helpers for efficient metrics collection
  - Comprehensive unit tests with 100% pass rate
  - Documented in docs/PROMETHEUS_METRICS.md with examples and Prometheus query patterns
- [x] [2025-12-30] Fixed release workflow race condition - implemented atomic release creation
  - Removed attach-to-release from go-binary-reusable.yaml
  - Centralized asset attachment in helm-release job
  - All assets (binaries, helm chart, SBOMs) now attached atomically
  - Fixed ci.yaml workflow to remove invalid attach-to-release parameter
- [x] [2025-12-30] Implemented updater asset availability validation with retry logic
  - Added HEAD request pre-flight validation before downloads
  - Implemented exponential backoff retry (3 attempts: 2s, 4s, 8s, max 30s)
  - Smart retry logic (only retries transient errors: 503, 504, 429, network issues)
  - Added configuration: update_download_max_retries and update_download_validate_assets
  - Updated http_downloader.go, downloader.go, updater.go, main.go, config.go
  - Documented in agent.conf.example
- [x] [2025-12-30] Linted and formatted all code changes (golangci-lint, go vet, gofmt)
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
