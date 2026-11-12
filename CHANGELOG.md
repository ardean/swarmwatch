# Changelog

## v0.5.19 - 2026-11-12

- **A dangling image keeps its name.** An untagged image left behind when a tag moves shows the repository and a short digest (`postgres@sha256:1444adda2e4b`) instead of `<dangling>`. Removal is still by image id.

**Upgrading:** nothing to configure.

## v0.5.18 - 2026-11-12

- **The service table sorts.** Click a column heading. CPU, memory, exposure, and vulnerabilities put the largest value first; the other columns go A to Z. Click again to flip. The choice stays in the address, so the minute reload keeps it, and an exposure filter stays on while you sort.

**Upgrading:** nothing to configure.

## v0.5.17 - 2026-11-12

- **The row stays the name.** A service labeled `swarmwatch.update=night` shows **night** on its row. Under the update line, its own line says when services marked with that name roll, and that **update all** leaves them until then. Another name, from `SWARMWATCH_UPDATE_LANES`, gets its own line.

**Upgrading:** nothing to configure.

## v0.5.16 - 2026-11-12

- **A schedule name says when it runs.** A service labeled `swarmwatch.update=night` shows **night, every day at 02:15** (the phrase for its cron), on the row and next to the schedule. The name is not fixed: `SWARMWATCH_UPDATE_NIGHT` is the lane named `night`, and `SWARMWATCH_UPDATE_LANES` adds more (`late=0 5 * * 1`). The fast schedule, **update all**, and the row button leave a named service alone.

**Upgrading:** nothing to configure. A host that already sets `SWARMWATCH_UPDATE_NIGHT` keeps that lane, and the page now spells out when it runs.

## v0.5.15 - 2026-11-12

- **The before command can start.** v0.5.14 called `/usr/bin/chroot`, which this image does not have, so `swarmwatch.before` failed before it ran. It now calls `/usr/sbin/chroot`.

**Upgrading:** replace 0.5.14. A service with `swarmwatch.before` did not run that command on 0.5.14, and its image was left as it was.

## v0.5.14 - 2026-11-12

- **A command before a night roll.** `swarmwatch.before` is an absolute command on the manager. swarmwatch runs it before that service's image moves, including on the night schedule. If the command fails, that service stays on the old image and is not rolled back. The fast schedule, **update all**, and the row button still leave a `swarmwatch.update=night` service alone.
- **Deploy flag.** `bin/deploy --update-night` sets `SWARMWATCH_UPDATE_NIGHT`.

**Upgrading:** nothing runs until a service sets `swarmwatch.before`. Set `--update-night` on a host that should roll services labeled `swarmwatch.update=night`.

## v0.5.13 - 2026-11-12

- **Update all.** With the update button on, the page shows **update all (N)** next to the schedule. It rolls every outdated service the row buttons would roll, one at a time, with the same wait and rollback. A night service and a service labeled `swarmwatch.update=false` stay put. An image that already failed is tried again, the same as its row button. The schedule still skips that image.

**Upgrading:** nothing to configure. The button appears when `SWARMWATCH_ALLOW_UPDATE=1` and at least one service is outdated.

## v0.5.12 - 2026-11-09

- **A night schedule for selected services.** `SWARMWATCH_UPDATE_NIGHT` is a second cron. A service labeled `swarmwatch.update=night` rolls only then. The fast schedule and the image-check button leave it alone. Pause stops both. `schedules.night` and `schedule: "night"` on `GET /api/v1/images` say which is which.

**Upgrading:** nothing moves until a service carries the label and `SWARMWATCH_UPDATE_NIGHT` is set. Without the night cron, that label is left out of both runs.

## v0.5.11 - 2026-11-09

- **The automatic check and roll can be paused.** `POST /api/v1/images/pause` stops that interval until `POST /api/v1/images/resume`. A roll already running finishes. The button can still check and roll once. The pause is remembered across a restart. `updates.paused` on `GET /api/v1/images` says which it is. The page shows that the interval is paused and has no button for it.

**Upgrading:** nothing to configure. The interval starts enabled.

## v0.5.10 - 2026-11-09

- **The API image check also rolls.** `POST /api/v1/images/check` still asks the registries immediately. When an update schedule or the update button is switched on, it then rolls every service the schedule would roll, one at a time, with the same rollback. A service the schedule leaves out stays put. An image that already failed to roll waits for a newer one, the same as a scheduled run. The step is marked as started from the button. A check does not start while a roll is running. `check.rolls` on `GET /api/v1/images` is true when a check will roll.
- **The page button still only checks.** The button next to scan now has no login, so it does not roll a service.

**Upgrading:** nothing to configure. A caller that posted `/api/v1/images/check` and relied on it never rolling will now roll when updates are enabled.

## v0.5.9 - 2026-11-08

- **The ports column stays one line.** Ports are plain text in a narrower column, so several ports no longer wrap into chips and stretch the row. A long list ellipsizes; the full list is on hover.

**Upgrading:** nothing to change.

## v0.5.8 - 2026-11-08

- **Published ports are on the service table.** A PORTS column lists each host port (`8096`, `53/udp`, or `8282→8080` when the container port differs). The same number on TCP and UDP stays two ports.
- **A Traefik `redirectRegex` route is not exposure.** Same as `redirectScheme`: a router that only redirects, such as an old hostname, is skipped.

**Upgrading:** nothing to change.

## v0.5.7 - 2026-11-06

- **Check images on request.** `POST /api/v1/images/check` asks the registries again whether each tag has a new image, and does not roll any service. One check runs at a time: a second request does not start another, and the page button cannot be pressed while one is running, the same as **scan now**. `GET /api/v1/images` lists each service (image, current or outdated, replicas, exposure, and whether the update schedule covers it) plus recent update steps. The API works with the pages off.
- **The same response names the automatic intervals.** `schedules` says when registries are asked and a service may roll (`every 5 minutes`, and the next time), when vulnerability scans may start, and when unused images are removed. Check images does not wait for those.

- **Needs attention is split by who can reach the service.** The closed summary counts findings on the internet
  (including internet·SSO), on the host, and not on the internet. A full disk or a down node stays in the host
  group. LAN and internal findings stay in the last group, and that count stays dim, so a critical finding there
  does not look like a public one. The crit and warn mark on each finding is unchanged, and so is the API status.

**Upgrading:** nothing to change.

## v0.5.6 - 2026-11-05

- **The page fits a 1080p window.** The service table uses the window width, and long cells ellipsize
  (the full text is on hover). "Needs attention" starts closed, so the service list is on screen without a scrollbar.

**Upgrading:** nothing to change.

## v0.5.5 - 2026-11-05

- **The page says whether automatic scans are on, and which services the schedule updates.** The status line
  shows `autoscan on (any time)` or the scan window. With an update schedule, each service is marked `auto` or
  `no` plus the reason (a label, not a swarm service, swarmwatch itself, or an unusual name). A service that is
  merely up to date stays `auto`: the schedule still watches it.
- **Fix: scanning a running image asked the registry and died on a rate limit.** After a digest-pinned
  update, Docker keeps `name@sha256:…` and drops the tag. Trivy was given `name:tag`, did not find it in the
  daemon, and pulled the tag from the registry. GHCR then answered `TOOMANYREQUESTS` (its `retry-after` is a
  fraction of a millisecond, so the pull is not retried). The scan now opens `name@digest`, which is the image
  the service is running.

**Upgrading:** nothing to change.

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
