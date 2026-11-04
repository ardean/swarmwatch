# Changelog

## v0.3.0 - 2026-11-04

An integration release: other tools can now read swarmwatch safely and reliably.

**Upgrading from 0.2.x. Read this first.**

- **Nothing is published by default any more.** `deploy/swarmwatch.yml` no longer has a `ports:` section. To keep
  the web UI on a port, add `-c swarmwatch.publish.yml` (or `bin/deploy -p 8590`). If you redeploy the new stack
  file without it, the UI is no longer reachable from outside; that is the intended, safer default.
- The stack now uses its own overlay network named `swarmwatch_net` (fixed name, attachable) instead of the stack's
  default network. Other stacks can join it with `external: true` and reach `http://swarmwatch:8590`.
- The "remove all listed" button asks for a checkbox instead of a JavaScript prompt, because the pages now run
  under a policy that forbids scripts.
- Error responses of `/api/findings` and `/api/vulns` are JSON (`{"error": "..."}`) like the v1 ones, not plain text.

Added:

- **`/api/v1`** with stable, documented types in the public package `pkg/api`: `/api/v1/findings`,
  `/api/v1/summary` (a few hundred bytes, for a status badge) and `/api/v1/vulns`. Within v1 fields are only added.
- **Structured findings.** Every finding has a stable `id`, a `kind`, `stack`, `image`, `exposure`, and for
  vulnerabilities `severity` and `count`, so a consumer no longer parses the message. `first_seen` says since when a
  finding exists (kept across restarts, in `/data`), so alerts can fire on new findings only. An unreachable
  manager does not make its old findings look new when it is back.
- **Filters** on findings: `min_level`, `swarm`, `stack`, `service`, `kind`. The status is that of the findings returned.
- **API token.** `SWARMWATCH_TOKEN_FILE` (a Docker secret, `deploy/swarmwatch.token.yml`) or `SWARMWATCH_TOKEN`
  requires a bearer token (at least 16 characters, constant-time comparison) on every `/api/` path. `/healthz`
  stays open. `SWARMWATCH_PEER_TOKEN` is what an instance sends to peers that require one.
- **`SWARMWATCH_DISABLE_UI`** serves only the API and `/healthz`: no web pages, no clean-up endpoint.
- **Go client** `pkg/client` for the v1 API.
- **`SWARMWATCH_SCAN_WINDOW`** (`02:00-05:00`) limits when the server starts Trivy scans; **`SWARMWATCH_CPU_LIMIT`**
  caps the container's CPU. Both are for small managers where a scan competes with the workloads.
- `swarmwatch version`; the version is built in and shown in `/api/v1/summary`.
- A GitHub release is created from this file when a `v*` tag is pushed, and the tag fails to build when its section
  is missing.

Security:

- Every response carries `Content-Security-Policy` (no scripts, nothing loaded from elsewhere), `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer`; API responses are `Cache-Control: no-store`.
- The HTTP server has read, write, idle and header-size limits.
- Rejected token attempts are logged at most once a minute, with a count.

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
