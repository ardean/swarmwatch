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
the container mounts the Docker socket and the web UI has no login.

On the manager:

```sh
curl -fsSLO https://raw.githubusercontent.com/ardean/swarmwatch/v0.2.1/deploy/swarmwatch.yml
SWARMWATCH_NAME=prod docker stack deploy -c swarmwatch.yml swarmwatch
```

Open `http://<manager>:8590/`. The first vulnerability scan downloads the Trivy database and scans each image
once, so the VULNS column says `not scanned` for the first few minutes. Read `swarmwatch.yml` before you deploy
it; it is short and every mount is commented.

Pin a release in production instead of `latest`:

```sh
SWARMWATCH_NAME=prod SWARMWATCH_IMAGE=ghcr.io/ardean/swarmwatch:0.2.1 docker stack deploy -c swarmwatch.yml swarmwatch
```

**Or from your workstation over ssh** (clone the repo, then): `bin/deploy <ssh-host> [-n name] [-d extra,disks] [-p port] [-i image] [-m memory] [-P peer-urls] [--allow-clean] [--no-registry-auth] [--local]`.
It sends `deploy/swarmwatch.yml` to the manager and runs the command above. `--local` builds the image on the manager from your checkout instead of pulling.

| Setting (environment of `docker stack deploy`) | Default | Meaning |
| --- | --- | --- |
| `SWARMWATCH_NAME` | `swarm` | name shown in the UI |
| `SWARMWATCH_IMAGE` | `ghcr.io/ardean/swarmwatch:latest` | image to run (pin a version) |
| `SWARMWATCH_PORT` | `8590` | published port of the UI |
| `SWARMWATCH_DISKS` | none | extra mount points to report; `/` and the Docker root are always shown |
| `SWARMWATCH_DOCKER_CONFIG` | none | the manager's `~/.docker/config.json`, so private registries can be checked for new digests (read-only, used in memory) |
| `SWARMWATCH_PEERS` | none | other swarmwatch instances whose Traefik proxies to this swarm, see [Exposure](#exposure) |
| `SWARMWATCH_ALLOW_CLEAN` | off | show the remove button, see [Unused images](#unused-images-and-containers) |
| `SWARMWATCH_MEMORY_LIMIT` | `2G` | memory cap of the container. A cap, not a reservation: idle use is about 30 MB. It protects the manager from a runaway scan of a very large image; set it too low and the container is killed mid-scan |
| `SWARMWATCH_DISK_PERCENT` / `SWARMWATCH_MEM_PERCENT` | `85` / `90` | warn above these percentages |

**Update:** re-run the same command (with a new `SWARMWATCH_IMAGE`, or `docker service update --image <image> swarmwatch_swarmwatch --force` for `latest`).
**Remove:** `docker stack rm swarmwatch && docker volume rm swarmwatch_swarmwatch-data`.

## Use

**Web UI** at `:8590/`: findings first (worst first, internet-facing ones on top), then one table per swarm.
Click a vulnerability count for the full list; click an exposure chip to filter.

**JSON API**, easy to poll from monitoring:

| URL | What |
| --- | --- |
| `/api/findings` | `{"status": "ok" \| "warn" \| "crit", "findings": [...]}` |
| `/api/overview` | the complete snapshot |
| `/api/vulns?swarm=…&service=…` | every vulnerability of a service's image (severity, package, installed → fixed version, advisory link) |
| `/api/exposure` | the Traefik routes this instance found (used by peers) |
| `/healthz` | liveness |

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
- **Hardening in the stack file:** read-only root filesystem, writable `/data` volume and `/tmp` tmpfs only, 2 GB memory limit, placed on a manager.
- **Supply chain:** GitHub Actions pinned by commit SHA, tests before every build, Trivy built from its release tag with patched dependencies, image published with build provenance and SBOM attestations, Dependabot for Go, Actions and Docker. Inspect with `docker buildx imagetools inspect ghcr.io/ardean/swarmwatch:latest --format '{{json .Provenance}}'`.
- **No authentication on the UI/API:** bind it to a trusted network or put it behind your authenticating reverse proxy. Report problems privately, see [SECURITY.md](SECURITY.md).

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
