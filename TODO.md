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
- [ ] Agent autoupdate
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
- [ ] K3s testing
- [ ] Microk8s testing
- [ ] GKE
- [ ] EKS
- [ ] AKS
- [ ] Scheduled tasks (rescan, clean up data, delete old data)
- [ ] Delete all data in container_instances and related tables, if there are no container_instances depending on that information. (done. I think)
- [ ] Trigger rescan of all container_images whenever the database for grype is updated
- [ ] Sending data using opentelemetry to a remove opentelemetry server
- [ ] Do proper autoupdate testing (work in progress)

## Recently Completed
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
