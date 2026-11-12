# swarmwatch

Read-only overview of Docker Swarms: what runs, what is outdated or vulnerable, what is reachable from the
internet, and how many resources it uses, so you know when to react.

[![Publish](https://github.com/ardean/swarmwatch/actions/workflows/publish.yml/badge.svg)](https://github.com/ardean/swarmwatch/actions/workflows/publish.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

- **Health:** replicas down, failed tasks, node status, CPU / memory / load / disk.
- **Patching:** outdated images (running digest vs. registry), Trivy vulnerabilities per image with links to every advisory.
- **Exposure:** every service marked `internet`, `internet·SSO`, `lan` or `internal`, derived from the real Traefik config and published ports.
- **Hygiene:** unused images and stopped containers, with an opt-in remove button.
- **Updating:** optionally rolls services to the newest image behind their tag, on a cron schedule or from a button, with rollback on failure and an audit log (a replacement for Dockupdater).

Every swarm is independent: one instance per swarm, nothing merged across swarms. swarmwatch never changes
anything on a swarm, with two opt-in exceptions that are off by default: the cleanup button and image updates.

## Install

You need: shell access to a Swarm **manager** with `docker`, and outbound HTTPS from it to `ghcr.io` (this image
and the Trivy database) and to the registries your images come from. Please skim [SECURITY.md](SECURITY.md) first:
the container mounts the Docker socket, and the web pages have no login.

Since 0.3.0 **nothing is published by default**. The stack only listens on its own overlay network
(`swarmwatch_net`); you choose how to reach it. On the manager:

```sh
BASE=https://raw.githubusercontent.com/ardean/swarmwatch/v0.5.16/deploy
curl -fsSLO $BASE/swarmwatch.yml -O $BASE/swarmwatch.publish.yml -O $BASE/swarmwatch.token.yml

# 1. Web UI on a published port, for a trusted network (the pages have no login)
SWARMWATCH_NAME=prod docker stack deploy -c swarmwatch.yml -c swarmwatch.publish.yml swarmwatch
# open http://<manager>:8590/

# 2. Data source for another tool: no port, API behind a token from a Docker secret
openssl rand -hex 32 | docker secret create swarmwatch_token -
SWARMWATCH_NAME=prod SWARMWATCH_DISABLE_UI=1 docker stack deploy -c swarmwatch.yml -c swarmwatch.token.yml swarmwatch
```

The first vulnerability scan downloads the Trivy database and scans each image once, so the VULNS column says
`not scanned` for the first few minutes. Read the stack files before you deploy them; they are short and every
mount is commented.

Pin a release in production instead of `latest`:

```sh
SWARMWATCH_NAME=prod SWARMWATCH_IMAGE=ghcr.io/ardean/swarmwatch:0.5.16 docker stack deploy -c swarmwatch.yml -c swarmwatch.publish.yml swarmwatch
```

**Or from your workstation over ssh** (clone the repo, then): `bin/deploy <ssh-host> [-n name] [-d extra,disks] [-p port] [-i image] [-m memory] [-c cpus] [-w scan-window] [-N network] [-P peer-urls] [--token-secret [name]] [--no-ui] [--allow-clean] [--allow-update] [--update-schedule cron] [--update-wait seconds] [--update-cleanup] [--clean-schedule cron] [--clean-keep age] [--no-registry-auth] [--local]`.
It sends the stack files to the manager and deploys them. Without `-p` nothing is published. `--local` builds the image on the manager from your checkout instead of pulling.

| Setting (environment of `docker stack deploy`) | Default | Meaning |
| --- | --- | --- |
| `SWARMWATCH_NAME` | `swarm` | name shown in the UI |
| `SWARMWATCH_IMAGE` | `ghcr.io/ardean/swarmwatch:latest` | image to run (pin a version) |
| `SWARMWATCH_PORT` | `8590` | published port, only with `swarmwatch.publish.yml` |
| `SWARMWATCH_NETWORK` | `swarmwatch_net` | name of the overlay network that other stacks join to reach `http://swarmwatch:8590` |
| `SWARMWATCH_TOKEN_SECRET` | `swarmwatch_token` | Docker secret holding the API token, only with `swarmwatch.token.yml` |
| `SWARMWATCH_DISABLE_UI` | off | serve only `/api` and `/healthz`: no web pages, no clean-up endpoint |
| `SWARMWATCH_DISKS` | none | extra mount points to report; `/` and the Docker root are always shown |
| `SWARMWATCH_DOCKER_CONFIG` | none | the manager's `~/.docker/config.json`, so private registries can be checked for new digests (read-only, used in memory) |
| `SWARMWATCH_PEERS` / `SWARMWATCH_PEER_TOKEN` | none | other swarmwatch instances whose Traefik proxies to this swarm, and the bearer token they require, see [Exposure](#exposure) |
| `SWARMWATCH_ALLOW_CLEAN` | off | show the remove button, see [Unused images](#unused-images-and-containers) |
| `SWARMWATCH_ALLOW_UPDATE` | off | show an update button on outdated services, see [Updating images](#updating-images) |
| `SWARMWATCH_UPDATE_SCHEDULE` | none | cron expression in `TZ`, e.g. `*/5 * * * *`: update outdated services then, except those with a `swarmwatch.update` name |
| `SWARMWATCH_UPDATE_NIGHT` | none | cron for the name `night`, e.g. `15 1 * * *`. The page shows that name and when it runs. The fast schedule and the button do not roll it |
| `SWARMWATCH_UPDATE_LANES` | none | more names, `name=cron` separated by semicolons, e.g. `late=0 5 * * 1`. A service labeled `swarmwatch.update=late` rolls then |
| `SWARMWATCH_UPDATE_WAIT` | `60` | seconds to wait after each updated service |
| `SWARMWATCH_UPDATE_CLEANUP` | off | remove unused images after an update run |
| `SWARMWATCH_CLEAN_SCHEDULE` | none | cron expression in `TZ`, e.g. `30 3 * * *`: remove unused images and stopped containers then, see [Unused images](#unused-images-and-containers) |
| `SWARMWATCH_CLEAN_KEEP` / `SWARMWATCH_CLEAN_KEEP_CONTAINERS` | `7d` / `24h` | how long after it was built an unused image, or a stopped container, stays |
| `SWARMWATCH_SCAN_WINDOW` | any time | when automatic scans may start, `HH:MM-HH:MM` in `TZ`, for example `02:00-05:00` (may wrap past midnight). A running scan finishes. The page's **scan now** button and the CLI `scan` ignore the window |
| `SWARMWATCH_MEMORY_LIMIT` | `2G` | memory cap of the container. A cap, not a reservation: idle use is about 30 MB. It protects the manager from a runaway scan of a very large image; set it too low and the container is killed mid-scan |
| `SWARMWATCH_CPU_LIMIT` | none | CPU cap, for example `0.5`. Trivy uses a core or more while it scans, so cap it on a small manager and pair it with a scan window |
| `SWARMWATCH_DISK_PERCENT` / `SWARMWATCH_MEM_PERCENT` | `85` / `90` | warn above these percentages |

**Update:** re-run the same command (with a new `SWARMWATCH_IMAGE`, or `docker service update --image <image> swarmwatch_swarmwatch --force` for `latest`).
**Remove:** `docker stack rm swarmwatch && docker volume rm swarmwatch_swarmwatch-data`.

## Use

**Web UI** at `:8590/`: findings first, then one table per swarm. The service table lists each published host port (`8096`, `53/udp`, or `8282→8080` when the container port differs). **Needs attention** stays closed and its summary counts three groups: on the internet (`internet` and `internet·SSO`), on the host (a full disk, a node down), and not on the internet (`lan` and `internal`). The home-only count stays dim even when a finding there is critical. Each finding keeps its own crit or warn mark.
Click a vulnerability count for the full list; click an exposure chip to filter. **Scan now** starts a Trivy scan of
every image immediately, including ones scanned recently, and ignores the scan window. One scan runs at a time. While
it runs the button stays on the page and cannot be pressed, and the page shows progress. It does not change the swarm,
but Trivy uses a core or more while it runs. With the pages off
there is no button, and scans start only inside the window.

**JSON API** under `/api/v1`, for monitoring and other tools. Types, field names and the rules for changing
them are in [`pkg/api`](pkg/api/api.go); within v1 fields are only added, never renamed or removed.

| URL | What |
| --- | --- |
| `/api/v1/summary` | status (`ok`, `info`, `warn`, `crit`), counts per level, age of the data, scan progress, status per swarm. A few hundred bytes, meant for a status badge |
| `/api/v1/findings` | the findings, worst first. Filters: `min_level=info\|warn\|crit`, `swarm`, `stack`, `service`, `kind`. The status covers the findings returned, so `?stack=shop` is the status of that stack |
| `/api/v1/vulns?swarm=…&service=…` | every vulnerability of a service's image (severity, package, installed → fixed version, advisory link) |
| `/api/v1/images` | each service and whether its tag still points at the running image (`current`, `outdated`, `unknown`), replicas, exposure, the update schedule mark (`auto`, `night`, or `no, …`), `check.running` / `check.last` / `check.rolls`, and `schedules` (the fast image roll, the night roll, the scan window, and the clean-up, with the next time when that is one moment). `check.rolls` is true when an API check will also roll. That roll is the fast schedule only |
| `POST /api/v1/images/check` | ask the registries again now. 202 accepted, 409 when a check or a roll is already running. When updates are switched on, the check then rolls every service the schedule would roll, one at a time. The page button next to **scan now** only asks the registries, and cannot be pressed while a check is running |
| `POST /api/v1/images/pause` | pause the automatic check and roll. 202, body `paused: true`. A roll already running finishes. The button can still check and roll once. Remembered across a restart. The page has no button for this |
| `POST /api/v1/images/resume` | let that interval fire again. 202, body `paused: false` |
| `/healthz` | liveness; fails when the data is older than five refresh intervals. Never needs a token |

Each finding has a stable `id` (`outdated:prod:shop_db`), a `kind`, `level`, `stack`, `service`, `image`,
`exposure`, for vulnerabilities `severity` and `count`, and `first_seen`, the time it first appeared and has not
gone away since. De-duplicate and alert on `id` and `first_seen`; do not parse `message`. The kinds are `unreachable`,
`node`, `memory`, `disk`, `replicas`, `failed_tasks`, `outdated`, `vulnerability`, `stale_scan` and `unused`.

```sh
curl -s -H "Authorization: Bearer $TOKEN" 'http://swarmwatch:8590/api/v1/findings?stack=shop&min_level=warn'
```

`/api/findings` and `/api/vulns` still answer with the same data for existing scripts. `/api/overview` (the raw
snapshot) and `/api/exposure` (how instances talk to each other) are not part of v1 and may change.

**Go client:** `go get github.com/ardean/swarmwatch@v0.5.16`, then

```go
c := client.New("http://swarmwatch:8590", token) // github.com/ardean/swarmwatch/pkg/client
sum, err := c.Summary(ctx)                        // sum.Status, sum.Counts.Crit, sum.Stale, ...
fs, err := c.Findings(ctx, client.FindingsQuery{Stack: "shop", MinLevel: "warn"})
```

The token is sent in clear text over plain `http`: use it on the overlay network or behind TLS.

**CI or cron check** without the service; exit code 0 ok, 1 warnings, 2 critical:

```sh
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v swarmwatch_swarmwatch-data:/data:ro -e SWARMWATCH_NAME=prod \
  ghcr.io/ardean/swarmwatch:latest check
```

(The `-v …-data` mount reuses the running instance's scan results; leave it out to skip vulnerability findings.)

**What raises a finding**

| Level | When |
| --- | --- |
| crit | manager unreachable; node not ready; fewer replicas running than desired; disk above threshold; a *fixable* CRITICAL vulnerability |
| warn | memory above threshold; failed tasks in the last 24 h; image outdated; a fixable HIGH vulnerability; an update that failed |
| info | stale scan data; unused images or containers that can be cleaned |

"Fixable" means the vulnerability has a patched version available. Findings on internet-exposed services are tagged `[internet]`.

## Exposure

Every service gets a level, worked out from the Traefik config and published ports:

| Level | Meaning |
| --- | --- |
| `internet` | has a Traefik route that is not restricted to private source ranges (or is the Traefik gateway itself) |
| `internet·SSO` | same, but every public route is behind forward-auth / basic-auth |
| `lan` | only `lan-only` (IP allow-list) routes, or a port published on the host |
| `internal` | no route, no published port: reachable only on the swarm's own networks |

Sources: `traefik.http.routers.*` labels, middlewares (labels and file provider), and the file-provider config of the
swarm's Traefik (found through its mounts), whose backends (`http://10.0.0.11:8080`) are matched to published ports on
the host that owns that IP. "internet" means *routed* to the public; whether your router or firewall forwards 80/443 to
Traefik is not visible from here. If another swarm's Traefik proxies to this swarm, give this instance that swarm's
swarmwatch URL (`SWARMWATCH_PEERS=http://swarm-a.example:8590`) so it can match those routes.

## Unused images and containers

Each swarm shows what can be cleaned up on its manager: images that no container (running or stopped) uses and no
service refers to by tag, dangling images, stopped standalone containers, and old images kept alive only by leftover
stopped swarm tasks. A service scaled to 0 keeps its image. Only the manager's engine is looked at.

Detection is read-only. The **remove button is off by default** because the UI has no login. Enable it per instance
with `SWARMWATCH_ALLOW_CLEAN=1` (`bin/deploy --allow-clean`). A click re-checks every listed item, removes only those
still unused, never uses `-f` (Docker refuses anything in use), accepts only same-origin POSTs and is logged
(`docker service logs swarmwatch_swarmwatch`). Volumes are never touched. "Up to X" is an upper bound: layers shared
with images you keep are not freed.

**On a schedule, with no button:** `SWARMWATCH_CLEAN_SCHEDULE` (a five-field cron expression in `TZ`, for example
`30 3 * * *`) removes the same things by itself. Nothing on the network can trigger it, so it works with
`SWARMWATCH_DISABLE_UI=1`. It keeps what is young: an unused image stays `SWARMWATCH_CLEAN_KEEP` (default `7d`) after it
was **built**, so a quick rollback needs no pull, and a stopped container stays `SWARMWATCH_CLEAN_KEEP_CONTAINERS`
(default `24h`). An item whose age is unknown is kept. A run is skipped while an update is rolling, and one missed
because swarmwatch was down is not caught up. This is the same as `docker container prune --filter until=24h` and
`docker image prune -a --filter until=168h`, but it uses swarmwatch's idea of "unused" (a tag a service names counts as
used) and logs what it removed.

## Updating images

Off by default, because it changes what runs. Two independent switches: `SWARMWATCH_UPDATE_SCHEDULE` (a five-field cron
expression in the container's `TZ`, for example `0 4 1 * *` for 04:00 on the first of each month) updates automatically,
and `SWARMWATCH_ALLOW_UPDATE=1` adds an **update** button next to every `OUTDATED` service, plus **update all**
for every one of those at once. Like the clean-up button it has no login and only accepts same-origin POSTs, so keep the page on a trusted network.

`POST /api/v1/images/pause` stops that interval until `POST /api/v1/images/resume`. A roll already running finishes, and `POST /api/v1/images/check` can still roll once. The pause is remembered on the data volume.

`POST /api/v1/images/check` does the same roll as the schedule, as soon as that check has asked the registries.
It needs the API token when one is set. It skips a service the schedule leaves out, and an image that already
failed to roll, until a newer image is published. The page button only asks the registries: that page has no login.

What an update does, one service at a time:

1. Only a service whose tag now points at a different image is touched; `current` and `unknown` are not.
   The command pins the digest the check found: `docker service update --with-registry-auth --image name:tag@sha256:…`.
   A bare tag would leave the old task running when the service already uses that tag, and Docker would still exit 0.
   Official images are a multi-arch index, and registries republish that index (new attestations) without changing
   the image. swarmwatch compares the manifest for the OS and architecture of the machine it runs on, so an index
   republish is `current`. A rebuilt image, including a pinned tag such as `postgres:17`, is `outdated`. A
   single-manifest image is compared by digest only. If the index cannot be read, the result is `unknown` and the
   service is left alone.
2. It waits until the service has converged. If the update fails or pauses, the service is rolled back
   (`docker service rollback`) and the run goes on with the next one. The failure shows as a `warn` finding
   (`update_failed`) until the service is up to date.
3. It waits `SWARMWATCH_UPDATE_WAIT` seconds before the next service, so a service that others depend on can settle.

Not touched: standalone containers (not swarm services), swarmwatch itself (update it by redeploying), and any
service labelled `swarmwatch.update=false`.

Optional service labels (under `deploy.labels` of the service, or on the container):

| Label | Meaning |
| --- | --- |
| `swarmwatch.update=false` | never update this service |
| `swarmwatch.update=<name>` | update this service only on the schedule of that name (`night`, or a name from `SWARMWATCH_UPDATE_LANES`). The row shows the name and when it runs. The fast schedule, **update all**, and the row button leave it |
| `swarmwatch.before=/path/cmd arg` | on the manager, run this command before the image moves. A failure skips the roll and does not roll back. The command is an absolute path plus args, with no shell syntax |
| `swarmwatch.then=stack_svc,other` | after this service was updated, restart these services (`docker service update --force`), for example a Zigbee bridge that loses its MQTT broker |
| `swarmwatch.wait=30` | seconds to wait after this service, before the restarts and the next service |

The Dockupdater labels `dockupdater.disable=true`, `dockupdater.starts` and `dockupdater.wait` are read as well, so
existing stack files keep working. A scheduled run that was missed because swarmwatch was down is not caught up.

Every step is logged and kept in an audit log on the data volume (`updates.json`, the last 100 steps) and shown on the
page under "recent updates". `SWARMWATCH_UPDATE_CLEANUP=1` removes images that no service uses any more after a run,
the same way the clean-up button does. Registry logins (`SWARMWATCH_DOCKER_CONFIG`) are forwarded to the nodes, so
private images work.

## Security notes for reviewers

- **Access it needs:** the Docker socket (root-equivalent on the manager whatever `:ro` says), `/` read-only (disk usage, Traefik config), optionally the manager's registry logins. Nothing else; it runs on one manager, never on workers.
- **It runs read-only commands:** `docker node/service/ps/inspect/stats/image ls`, `df`, `/proc`. The write paths are the opt-ins: cleanup (`docker container rm`, `docker image rm`) and updates (`docker service update`, `docker service rollback`).
- **Outbound connections:** the registries of your images (digest check) and `ghcr.io` / `mirror.gcr.io` (Trivy database). No telemetry, no phone-home; Trivy telemetry is disabled.
- **Hardening in the stack file:** read-only root filesystem, writable `/data` volume and `/tmp` tmpfs only, 2 GB memory limit, placed on a manager, no published port unless you add `swarmwatch.publish.yml`.
- **API token:** `SWARMWATCH_TOKEN_FILE` (a Docker secret) makes every `/api/` request need a bearer token of at least 16 characters, compared in constant time. `/healthz` stays open. The token does not cover the web pages: set `SWARMWATCH_DISABLE_UI=1` when only the API is needed.
- **Responses:** every response carries `Content-Security-Policy` (no scripts, no outside loads), `X-Frame-Options: DENY`, `nosniff` and `Referrer-Policy: same-origin`; API responses are `no-store`. The server sets read, write and header limits.
- **Supply chain:** GitHub Actions pinned by commit SHA, tests before every build, Trivy built from its release tag with patched dependencies, image published with build provenance and SBOM attestations, Dependabot for Go, Actions and Docker. Inspect with `docker buildx imagetools inspect ghcr.io/ardean/swarmwatch:latest --format '{{json .Provenance}}'`.
- **No login on the web pages:** bind them to a trusted network, turn them off, or put them behind your authenticating reverse proxy. Report problems privately, see [SECURITY.md](SECURITY.md).

## Watching many swarms from one machine (ssh)

```sh
go build -o bin/swarmwatch ./cmd/swarmwatch
mkdir -p ~/.config/swarmwatch && cp swarmwatch.example.yaml ~/.config/swarmwatch/config.yaml
swarmwatch                 # overview
swarmwatch check           # only what needs attention; exit 0 ok / 1 warn / 2 crit
swarmwatch scan            # Trivy scan of images whose result is stale (via docker on each manager)
swarmwatch scan -force     # rescan every image; the page's scan now button does this too
swarmwatch serve           # the same web UI for all swarms in the config file
```

This uses your ssh keys and `ssh_config` to run the same read-only docker commands on each manager. Cross-swarm
Traefik routes are matched automatically in this mode.

## Limits

- CPU / memory only cover containers on the manager the instance runs on; worker nodes are not included yet.
- Images built locally (no registry digest) show `-` for update status.
- "Outdated" means the image for this machine changed. A rebuilt tag, including a pin such as `postgres:17`, is
  outdated. A republished multi-arch index with the same image for this OS and architecture is not. The comparison
  uses the machine swarmwatch runs on, which is the node that runs the service when the swarm has one node.
- Registry logins that live in a credential helper instead of `config.json` cannot be reused.

## Contributing

`go vet ./... && go test -race ./...` must pass; CI runs the same plus `gofmt`. Issues and pull requests are welcome.

## License

[MIT](LICENSE)
