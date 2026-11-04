# swarmwatch

Read-only overview of Docker Swarms: what runs, what is outdated or vulnerable, what is reachable from the
internet, and how many resources it uses, so you know when to react.

[![Publish](https://github.com/ardean/swarmwatch/actions/workflows/publish.yml/badge.svg)](https://github.com/ardean/swarmwatch/actions/workflows/publish.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

- **Health:** replicas down, failed tasks, node status, CPU / memory / load / disk.
- **Patching:** outdated images (running digest vs. registry), Trivy vulnerabilities per image with links to every advisory.
- **Exposure:** every service marked `internet`, `internet·SSO`, `lan` or `internal`, derived from the real Traefik config and published ports.
- **Hygiene:** unused images and stopped containers, with an opt-in remove button.

Every swarm is independent: one instance per swarm, nothing merged across swarms. swarmwatch never changes
anything on a swarm (the only exception is the opt-in cleanup button, off by default).

## Install

You need: shell access to a Swarm **manager** with `docker`, and outbound HTTPS from it to `ghcr.io` (this image
and the Trivy database) and to the registries your images come from. Please skim [SECURITY.md](SECURITY.md) first:
the container mounts the Docker socket, and the web pages have no login.

Since 0.3.0 **nothing is published by default**. The stack only listens on its own overlay network
(`swarmwatch_net`); you choose how to reach it. On the manager:

```sh
BASE=https://raw.githubusercontent.com/ardean/swarmwatch/v0.3.1/deploy
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
SWARMWATCH_NAME=prod SWARMWATCH_IMAGE=ghcr.io/ardean/swarmwatch:0.3.1 docker stack deploy -c swarmwatch.yml -c swarmwatch.publish.yml swarmwatch
```

**Or from your workstation over ssh** (clone the repo, then): `bin/deploy <ssh-host> [-n name] [-d extra,disks] [-p port] [-i image] [-m memory] [-c cpus] [-w scan-window] [-N network] [-P peer-urls] [--token-secret [name]] [--no-ui] [--allow-clean] [--no-registry-auth] [--local]`.
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
| `SWARMWATCH_SCAN_WINDOW` | any time | when scans may start, `HH:MM-HH:MM` in `TZ`, for example `02:00-05:00` (may wrap past midnight). A running scan finishes; the CLI `scan` ignores it |
| `SWARMWATCH_MEMORY_LIMIT` | `2G` | memory cap of the container. A cap, not a reservation: idle use is about 30 MB. It protects the manager from a runaway scan of a very large image; set it too low and the container is killed mid-scan |
| `SWARMWATCH_CPU_LIMIT` | none | CPU cap, for example `0.5`. Trivy uses a core or more while it scans, so cap it on a small manager and pair it with a scan window |
| `SWARMWATCH_DISK_PERCENT` / `SWARMWATCH_MEM_PERCENT` | `85` / `90` | warn above these percentages |

**Update:** re-run the same command (with a new `SWARMWATCH_IMAGE`, or `docker service update --image <image> swarmwatch_swarmwatch --force` for `latest`).
**Remove:** `docker stack rm swarmwatch && docker volume rm swarmwatch_swarmwatch-data`.

## Use

**Web UI** at `:8590/`: findings first (worst first, internet-facing ones on top), then one table per swarm.
Click a vulnerability count for the full list; click an exposure chip to filter.

**JSON API** under `/api/v1`, for monitoring and other tools. Types, field names and the rules for changing
them are in [`pkg/api`](pkg/api/api.go); within v1 fields are only added, never renamed or removed.

| URL | What |
| --- | --- |
| `/api/v1/summary` | status (`ok`, `info`, `warn`, `crit`), counts per level, age of the data, scan progress, status per swarm. A few hundred bytes, meant for a status badge |
| `/api/v1/findings` | the findings, worst first. Filters: `min_level=info\|warn\|crit`, `swarm`, `stack`, `service`, `kind`. The status covers the findings returned, so `?stack=shop` is the status of that stack |
| `/api/v1/vulns?swarm=…&service=…` | every vulnerability of a service's image (severity, package, installed → fixed version, advisory link) |
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

**Go client:** `go get github.com/ardean/swarmwatch@v0.3.1`, then

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
| warn | memory above threshold; failed tasks in the last 24 h; image outdated; a fixable HIGH vulnerability |
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

## Security notes for reviewers

- **Access it needs:** the Docker socket (root-equivalent on the manager whatever `:ro` says), `/` read-only (disk usage, Traefik config), optionally the manager's registry logins. Nothing else; it runs on one manager, never on workers.
- **It runs read-only commands:** `docker node/service/ps/inspect/stats/image ls`, `df`, `/proc`. The one write path is the opt-in cleanup (`docker container rm`, `docker image rm`).
- **Outbound connections:** the registries of your images (digest check) and `ghcr.io` / `mirror.gcr.io` (Trivy database). No telemetry, no phone-home; Trivy telemetry is disabled.
- **Hardening in the stack file:** read-only root filesystem, writable `/data` volume and `/tmp` tmpfs only, 2 GB memory limit, placed on a manager, no published port unless you add `swarmwatch.publish.yml`.
- **API token:** `SWARMWATCH_TOKEN_FILE` (a Docker secret) makes every `/api/` request need a bearer token of at least 16 characters, compared in constant time. `/healthz` stays open. The token does not cover the web pages: set `SWARMWATCH_DISABLE_UI=1` when only the API is needed.
- **Responses:** every response carries `Content-Security-Policy` (no scripts, no outside loads), `X-Frame-Options: DENY`, `nosniff` and `no-referrer`; API responses are `no-store`. The server sets read, write and header limits.
- **Supply chain:** GitHub Actions pinned by commit SHA, tests before every build, Trivy built from its release tag with patched dependencies, image published with build provenance and SBOM attestations, Dependabot for Go, Actions and Docker. Inspect with `docker buildx imagetools inspect ghcr.io/ardean/swarmwatch:latest --format '{{json .Provenance}}'`.
- **No login on the web pages:** bind them to a trusted network, turn them off, or put them behind your authenticating reverse proxy. Report problems privately, see [SECURITY.md](SECURITY.md).

## Watching many swarms from one machine (ssh)

```sh
go build -o bin/swarmwatch ./cmd/swarmwatch
mkdir -p ~/.config/swarmwatch && cp swarmwatch.example.yaml ~/.config/swarmwatch/config.yaml
swarmwatch                 # overview
swarmwatch check           # only what needs attention; exit 0 ok / 1 warn / 2 crit
swarmwatch scan            # Trivy scan of all images (via docker on each manager)
swarmwatch serve           # the same web UI for all swarms in the config file
```

This uses your ssh keys and `ssh_config` to run the same read-only docker commands on each manager. Cross-swarm
Traefik routes are matched automatically in this mode.

## Limits

- CPU / memory only cover containers on the manager the instance runs on; worker nodes are not included yet.
- Images built locally (no registry digest) show `-` for update status.
- "Outdated" is digest-based: it also fires for pinned tags like `postgres:17` when the tag was rebuilt.
- Registry logins that live in a credential helper instead of `config.json` cannot be reused.

## Contributing

`go vet ./... && go test -race ./...` must pass; CI runs the same plus `gofmt`. Issues and pull requests are welcome.

## License

[MIT](LICENSE)
