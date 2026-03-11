# bjorn2scan TODO List

## Active Tasks
- [ ] None currently

## In Progress
- [ ] None currently

## Backlog
- [ ] Remove gomezboe.com dependency from grype database update tests
  - [ ] Replace `scripts/test-grype-db-updater` with self-contained unit tests
  - [ ] Consider mocking distribution.Client for IsUpdateAvailable tests
  - [ ] Or set up local test fixtures that don't require external hosting
- [ ] Use kube-system namespace UID as cluster_id in metrics (Kubernetes mode only)
  - [ ] Auto-detect cluster ID from kube-system namespace UID
  - [ ] Fall back to hostname or configurable ID for non-Kubernetes deployments
  - [ ] Add cluster_id label to relevant metrics
- [ ] Scanner upgrade stability
- [ ] Scanner stability in general
- [ ] Grafana data integrity
- [ ] Add host_ip tracking to metrics (requires storing Kubernetes node IP in database or querying K8s API)
- [ ] Pick up node tags!
- [ ] Clean up agent configuration management:
  - [ ] Make defaults.conf the single source of truth (embed in binary at compile time)
  - [ ] Move defaults from scanner-core to component-specific (agent, k8s-scan-server)
  - [ ] Ensure agent.conf.example matches actual code defaults
  - [ ] Add --show-config flag to display current configuration
- [ ] Node scanning
- [ ] Remote workers for increased performance?
- [ ] Test bjorn2scan-agent install.sh on major Linux distributions:
  - [X] Ubuntu 22.04/24.04 LTS
  - [X] Debian 11/12
  - [ ] Alpine Linux (BusyBox compatibility)
  - [ ] Amazon Linux 2/2023
  - [ ] RHEL/Rocky/AlmaLinux 8/9
  - [ ] Fedora (latest)
  - [ ] Raspberry Pi OS (ARM64)
- [ ] Other K8s distributions
  - [ ] GKE
  - [ ] EKS
  - [ ] AKS
- [ ] Implement cosign signature verification for auto-updates (verifier.go currently returns nil)
  - [ ] Agent binary verification
  - [ ] Helm chart verification
  - [ ] Add SHAs to values.yaml
- [ ] Make checkHealth() retry interval configurable (currently hardcoded to 2 seconds)

## Recently Completed
- [x] [2026-03-11] Implemented code simplification suggestions (net ~330 lines removed)
  - Created `scanner-core/handlers/queryhelpers.go` with shared SQL filter building helpers
  - Consolidated 4 CSV export functions into single `exportQueryResultAsCSV()` function
  - Extracted vulnerability label building in metrics with `buildVulnerabilityLabels()` helper
  - Refactored `buildImagesQuery`, `buildPodsQuery`, `buildNamespaceSummaryQuery`, `buildDistributionSummaryQuery`
  - Refactored `collectScannedContainerMetrics`, `collectVulnerabilityMetrics`, `collectVulnerabilityExploitedMetrics`, `collectVulnerabilityRiskMetrics`
- [x] [2026-03-11] Added integration tests for database migrations with realistic data
  - Created `scanner-core/database/migration_integration_test.go`
  - Tests populate database with realistic data before running migrations
  - Includes deadlock timeout detection (30 seconds)
  - Tests for v25 (architecture), v27 (reference), concurrent access, and large datasets
  - Addresses the v25 bug that caused 30k+ pod restarts in production
- [x] [2026-01-18] Fixed grype database timestamp handling issues
  - Added RFC3339 parsing support for grype v6 timestamps in `vulndb/database_updater.go`
  - Fixed stale timestamp issue in `grype/grype.go` by reading actual timestamp from SQLite after loading
  - Added `extractGrypeDBBuiltFromJSON()` in `database/scanning.go` to ensure `grype_db_built` column matches scan JSON
  - Root cause: grype's `LoadVulnerabilityDB()` returns cached/stale timestamps, causing repeated rescans every 30 minutes
- [x] [2026-01-03] Fixed agent auto-update failure caused by corrupted atom feed titles
  - Root cause: GitHub shows tag annotation content in `<title>` before release is created
  - Added `extractTagFromID()` and `isReleaseReady()` to handle tag vs release detection
- [x] [2026-01-03] Added `currentVersion` field to `/api/update/status` endpoint
- [x] [2026-01-03] Updated vulnerability metrics to multiply by instance count
- [x] [2025-12-30] Implemented Prometheus metrics endpoint at /metrics
- [x] [2025-12-30] Fixed release workflow race condition - implemented atomic release creation
- [x] [2025-12-30] Implemented updater asset availability validation with retry logic
- [x] [2025-12-29] Fixed URL filter parameter application and navigation in web UI
- [x] [2025-12-29] Fixed agent systemd service to work without Docker installed

---

**Notes:**
- This file persists across Claude conversation contexts
- Claude reads this at session start to understand current work
- Tasks move from Active → In Progress → Recently Completed
- Keep Recently Completed items for ~30 days for reference
