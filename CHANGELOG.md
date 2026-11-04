# Changelog

## v0.2.1 - 2026-11-04

- `SWARMWATCH_MEMORY_LIMIT` (`bin/deploy -m`) sets the container memory cap; default stays 2G. Documented why the cap exists and that it is not a reservation.

## v0.2.0 - 2026-11-04

- Detect unused images and stopped containers (also images pinned only by leftover swarm tasks); shown in the UI, CLI, findings and API.
- Opt-in remove button (`--allow-clean`): re-checks at click time, never forces, same-origin POST only.
- `deploy/swarmwatch.yml`: a plain stack file to deploy without the ssh script; read-only root filesystem; `bin/deploy -i` pins an image.
- Clean actions are logged. Image published with provenance and SBOM attestations.

## v0.1.0

First public release.

- Read-only overview of independent Docker Swarms: stacks, services, replicas, failed tasks.
- CPU, memory, load and disk usage per swarm manager.
- Outdated-image detection by comparing running and registry digests.
- Trivy vulnerability scans with a per-service detail page and a 24h cache.
- Exposure levels (`internet`, `internet-sso`, `lan`, `internal`) derived from Traefik labels, file-provider config and published ports.
- Web UI, JSON API (`/api/findings`, `/api/overview`, `/api/exposure`, `/api/vulns`) and a CLI with `check` exit codes.
- One-command deploy (`bin/deploy`) and a multi-swarm mode over ssh.
