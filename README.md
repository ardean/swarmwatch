# swarmwatch

Read-only overview of Docker Swarms: what runs, what is outdated or vulnerable, and how many
resources it uses — so you know when to react.

Every swarm is independent (own stacks, own findings, own instance). Nothing is merged across swarms,
and swarmwatch never changes anything on them.

[![Publish](https://github.com/ardean/swarmwatch/actions/workflows/publish.yml/badge.svg)](https://github.com/ardean/swarmwatch/actions/workflows/publish.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Requirements: Docker Swarm manager(s) reachable over ssh, with `docker` available. Go 1.27+ only if you build
from source. Please read [SECURITY.md](SECURITY.md) first: the service mounts the Docker socket and has no
built-in authentication.

## Run one instance per swarm (recommended)

```sh
bin/deploy swarm-a.local  -d /mnt/data     # deploy stack "swarmwatch" using ghcr.io/ardean/swarmwatch:latest
bin/deploy swarm-b.local -d /mnt/data2 --local   # no ghcr login there: build the image on the host instead
bin/deploy my-other-swarm  -n homelab -p 8591 # any further swarm: same command
```

`bin/deploy <ssh-host> [-n name] [-d extra,disks] [-p port] [-P peer-urls] [--allow-clean] [--local]` needs only ssh + docker on a
swarm manager. The image is built by GitHub Actions (`.github/workflows/publish.yml`: test, then push to
`ghcr.io/ardean/swarmwatch`). If you fork this and keep your package private, the manager needs `docker login ghcr.io`
with a token that can read packages; `--local` skips the pull by building on the host. Re-run to update. Each instance serves:

| URL | What |
| --- | --- |
| `:8590/` | web overview (auto-refresh) |
| `:8590/api/findings` | `{status: ok/warn/crit, findings: [...]}` — easy to poll from Home Assistant / Node-RED |
| `:8590/api/overview` | full snapshot as JSON |
| `:8590/?exposure=internet` | the overview filtered to one exposure level (`internet`, `internet-sso`, `lan`, `internal`) |
| `:8590/api/exposure` | the Traefik file routes this instance found — peers use it, see below |
| `:8590/vulns?swarm=…&service=…` | every vulnerability of a service's image (severity, package, installed → fixed version, title, link to the advisory); linked from the table and the findings list |
| `:8590/api/vulns?swarm=…&service=…` | the same as JSON |
| `:8590/healthz` | container healthcheck |

The service is pinned to a manager, mounts the Docker socket (read-only flag, but the socket is
powerful — same trust level as `dockupdater`/Traefik) and `/` read-only for disk usage. It has **no
authentication**: keep the port LAN-only or put it behind your auth proxy.

## Or: one machine watching many swarms over ssh

```sh
go build -o bin/swarmwatch ./cmd/swarmwatch
mkdir -p ~/.config/swarmwatch && cp swarmwatch.example.yaml ~/.config/swarmwatch/config.yaml
swarmwatch                 # overview
swarmwatch check           # only what needs attention; exit 0 ok / 1 warn / 2 crit
swarmwatch scan            # Trivy scan of all images (via docker on each manager)
swarmwatch serve           # same web UI, but for all swarms in the config file
```

## Unused images and containers

Each swarm shows what can be cleaned up on its manager: images that no container (running or stopped) uses and
no service refers to by tag, dangling images, stopped standalone containers, and old images kept alive only by
leftover stopped swarm tasks. A service scaled to 0 keeps its image. It appears as an info finding, a `cleanup`
line in the CLI, a collapsible list in the UI and `unused` in `/api/overview`. Only the manager's engine is
looked at; other nodes are not visible.

Detection is always read-only. The **remove button is off by default** because the UI has no login. Enable it per
instance with `bin/deploy <host> --allow-clean` (`SWARMWATCH_ALLOW_CLEAN=1`, `serve.allow_clean: true`). A click
re-checks every listed item and removes only those still unused, never with `-f` (Docker refuses anything in use),
and it accepts only same-origin POSTs. Volumes are never touched. "Up to X" is an upper bound: layers shared with
images you keep are not freed.

## Exposure

Every service gets a level, worked out from the real Traefik config and published ports:

| Level | Meaning |
| --- | --- |
| `internet` | has a Traefik route that is not restricted to private source ranges (or is the Traefik gateway itself) |
| `internet·SSO` | same, but every public route is behind forward-auth / basic-auth |
| `lan` | only `lan-only` (IP allow-list) routes, or a port published on the host |
| `internal` | no route, no published port: reachable only on the swarm's own networks |

Sources: `traefik.http.routers.*` labels, middlewares (labels and file provider), and the file-provider
config of the swarm's Traefik (found through its mounts), whose backends (`http://10.0.0.11:8080`) are
matched to published ports on the host that owns that IP. "internet" means *routed* to the public — whether
your router forwards 80/443 to Traefik is not visible from here. Findings on internet-exposed services carry
an `[internet]` tag and sort first.

If another swarm's Traefik proxies to this swarm (swarm-a -> swarm-b), give this instance its URL so it can
match those routes: `bin/deploy swarm-b.local -P http://swarm-a.local:8590`. A single machine watching all
swarms (`swarmwatch` CLI with a config file) does this matching automatically.

## What it reports

| Signal | How |
| --- | --- |
| Replicas down / failed tasks (24h) | `docker service ls` / `service ps` |
| CPU / memory per service, load, disks | `docker stats`, `/proc`, `df` on the manager |
| Outdated image | running digest vs. registry digest for the same tag; reuses the manager's `~/.docker/config.json` logins (mounted read-only into the container, used in memory only) |
| Vulnerabilities | Trivy per image, total and *fixable* per severity; rescanned every 24h, cached in the `swarmwatch-data` volume |

## Limits (v1)

- CPU/memory only cover containers on the manager the instance runs on; worker nodes are not included yet.
- Images built locally (no registry digest) show `-` for update status.
- "Outdated" is digest-based: it also fires for pinned tags like `postgres:17` when the tag was rebuilt.

## License

[MIT](LICENSE)
