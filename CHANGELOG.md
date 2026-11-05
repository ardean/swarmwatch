# Changelog

## v0.5.4 - 2026-11-05

- **Scan now.** The web page has a button that starts a Trivy scan of every image immediately, including images
  scanned recently. It ignores `SWARMWATCH_SCAN_WINDOW`. One scan runs at a time: while it runs the button stays
  visible and cannot be pressed, and another request does not start a second scan. With `SWARMWATCH_DISABLE_UI=1`
  there is no button, and automatic scans still start only inside the window.

**Upgrading:** nothing to change. The button is there after you redeploy this version.

## v0.5.3 - 2026-11-05

- **Fix: updating a service that already uses its tag did not pull the new image.** The command passed the tag
  only. Docker keeps the running task when the image string does not change and exits 0, so the update was
  recorded as successful and tried again at every tick. The command now pins `tag@sha256:…` with the digest
  the check already found. A pull that fails is still remembered by that digest and not retried.

**Upgrading:** nothing to change.

## v0.5.2 - 2026-11-05

- **Fix: a republished multi-arch index looked like a new image.** Official images are an index of per-platform
  manifests. Registries republish that index (new attestations) without changing the image a machine runs, and a
  service often stores the index digest from the day it was deployed. Those digests differ, so the service showed
  as outdated. The check now compares the manifest for this machine's OS and architecture. A single-manifest
  image is unchanged: only an equal digest counts. If the index cannot be read, the result is unknown, not
  outdated, so an updater does not roll it.

**Upgrading:** nothing to change.

## v0.5.1 - 2026-11-05

- **Fix: a scheduled update could miss a new image for up to an hour.** Registry results are remembered for
  `registry_ttl` (default one hour), and the scheduled run reused them. A service that was "up to date" when the
  last check ran stayed "up to date" after you pushed a new image, so a `*/5 * * * *` schedule rolled it out late.
  A scheduled run now forgets the remembered results and asks the registries again. The pages and the API keep
  using the cache.

**Upgrading:** nothing to change. With a schedule, a pushed image is now live at the next tick.

## v0.5.0 - 2026-11-04

- **Scheduled clean-up.** `SWARMWATCH_CLEAN_SCHEDULE` (cron, in `TZ`) removes unused images and stopped containers on
  its own, with no button and no web page needed, so it works with `SWARMWATCH_DISABLE_UI=1`. An unused image stays
  `SWARMWATCH_CLEAN_KEEP` (default `7d`) after it was built, so a quick rollback needs no pull; a stopped container stays
  `SWARMWATCH_CLEAN_KEEP_CONTAINERS` (default `24h`). Items of unknown age are kept. A run is skipped while an update
  rolls. `bin/deploy` gained `--clean-schedule` and `--clean-keep`; the config file gained a `clean:` section.
- Unlike `SWARMWATCH_UPDATE_CLEANUP`, which removes every unused image right after an update run, this one runs on its
  own schedule and keeps recent images. Use it to replace a `docker image prune` cron job or sidecar.

**Upgrading:** nothing changes unless you set `SWARMWATCH_CLEAN_SCHEDULE`.

## v0.4.2 - 2026-11-04

- **A scheduled run no longer retries an image that already failed.** An update that failed and was rolled back left the
  service outdated, so a schedule such as `*/5 * * * *` rolled the same broken image out and back at every tick. The
  run now remembers the registry digest it tried; it skips that service until the tag points at another digest. The
  `update_failed` finding stays. The button still tries again when you press it.

## v0.4.1 - 2026-11-04

- **Fix: update column showed `-` for services deployed without a pinned digest.** `docker stack deploy` leaves the
  `@sha256:` out of the service spec when it cannot reach the registry at deploy time, and swarmwatch then never
  compared the service. It now falls back to the registry digest of the image the running container was pulled as, so
  those services show `current` or `OUTDATED` (and can be updated). Images that were built locally and never pulled
  still show `-`.

## v0.4.0 - 2026-11-04

swarmwatch can now keep a swarm up to date, so a separate updater such as Dockupdater (unmaintained, with known
vulnerabilities of its own) is no longer needed. Everything new is **off by default**.

- **Scheduled updates.** `SWARMWATCH_UPDATE_SCHEDULE` takes a five-field cron expression in `TZ` (for example
  `0 4 1 * *`). On each match every service whose registry digest differs from the running one is rolled to the newest
  image behind its tag with `docker service update --with-registry-auth --image <name:tag>`, one at a time, waiting
  `SWARMWATCH_UPDATE_WAIT` seconds (default 60) after each. A failed update is rolled back with `docker service rollback`
  and the run continues. `SWARMWATCH_UPDATE_CLEANUP=1` removes images that are unused afterwards.
- **Update button.** `SWARMWATCH_ALLOW_UPDATE=1` shows an **update** button on outdated services, with the same
  same-origin protection as the clean-up button. The roll runs in the background.
- **Labels.** `swarmwatch.update=false` excludes a service; `swarmwatch.then=<service,...>` restarts other services after
  this one was updated and `swarmwatch.wait=<seconds>` sets the pause. The Dockupdater labels `dockupdater.disable`,
  `dockupdater.starts` and `dockupdater.wait` mean the same and keep working.
- **Audit log.** Every step is logged and kept in `updates.json` on the data volume (last 100) and listed on the page.
- **New finding** `update_failed` (warn): the last update of a service failed and it is still outdated.
- `bin/deploy` gained `--allow-update`, `--update-schedule`, `--update-wait` and `--update-cleanup`; the config file gained
  an `update:` section.
- Standalone containers and swarmwatch itself are never updated. `/api/v1` only gained the `update_failed` kind.
- The security notes now say `Referrer-Policy: same-origin` (changed in 0.3.4).

**Upgrading:** nothing changes unless you set one of the new options. A missed scheduled run (swarmwatch was down at that
minute) is not caught up. Read the "Updating (opt-in)" entry in SECURITY.md before enabling the button.

## v0.3.4 - 2026-11-04

- Fixes "cross-site request refused" on the clean-up button since v0.3.0. The `Referrer-Policy: no-referrer` header made
  browsers send `Origin: null` with the form, which the same-origin check refused. The policy is now `same-origin`.

## v0.3.3 - 2026-11-04

- Clean-up finds untagged ("dangling") images again. Docker 29 no longer lists them in a plain `docker image ls`, so the
  old versions left behind when a tag like `:latest` is pulled again were missing from "unused images" and could not be
  cleaned up from the page.

## v0.3.2 - 2026-11-04

- Fixes the container being OOM-killed in a restart loop while scanning large images (for example a 2.4 GB Home Assistant
  or Paperless image). Trivy exports the image from the Docker daemon into the temp directory, which in the container
  is RAM-backed `/tmp` and counted against the memory limit. The image now sets `TMPDIR=/data/tmp` (on the data volume),
  and leftovers of a killed scan are removed. No configuration change needed; the data volume must have room for the
  largest image while it is scanned.

## v0.3.1 - 2026-11-04

- The module declares Go 1.26 instead of 1.27.3, so programs on an older Go can import `pkg/api` and `pkg/client`
  without being forced onto a newer toolchain. No change to the server. Use this instead of v0.3.0 if you import the Go client.

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
