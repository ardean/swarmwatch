# Changelog

## Unreleased

- Detect unused images and stopped containers (also images pinned only by leftover swarm tasks); shown in the UI, CLI, findings and API.
- Opt-in remove button (`--allow-clean`): re-checks at click time, never forces, same-origin POST only.

## v0.1.0

First public release.

- Read-only overview of independent Docker Swarms: stacks, services, replicas, failed tasks.
- CPU, memory, load and disk usage per swarm manager.
- Outdated-image detection by comparing running and registry digests.
- Trivy vulnerability scans with a per-service detail page and a 24h cache.
- Exposure levels (`internet`, `internet-sso`, `lan`, `internal`) derived from Traefik labels, file-provider config and published ports.
- Web UI, JSON API (`/api/findings`, `/api/overview`, `/api/exposure`, `/api/vulns`) and a CLI with `check` exit codes.
- One-command deploy (`bin/deploy`) and a multi-swarm mode over ssh.
