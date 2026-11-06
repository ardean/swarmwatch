# Security

## Reporting a vulnerability

Please report security issues privately through GitHub's
[private vulnerability reporting](https://github.com/ardean/swarmwatch/security/advisories/new)
rather than a public issue. Include what you found, how to reproduce it, and the version or commit.

## Trust model

swarmwatch is a **read-only** monitoring tool, but you should understand what it can reach:

- **Docker socket.** The container mounts `/var/run/docker.sock`. Even with the `:ro` flag, access to the
  socket is effectively root on the host. Run it only on managers you already trust it with.
- **Host filesystem.** `/` is bind-mounted read-only at `/host` to report disk usage and to read the
  Traefik config for exposure analysis. That config can contain secrets; swarmwatch reads it but does not
  store or serve it.
- **Registry credentials.** If present, the manager's `~/.docker/config.json` is mounted read-only and used
  in memory to query registries. It is never written elsewhere or exposed through the API.
- **Cleaning (opt-in).** Off by default. With `--allow-clean` anyone who can reach the UI can remove unused images and stopped containers on that manager (not volumes, not anything in use, never forced). Enable it only on a network where that is acceptable, or behind an authenticating proxy.
- **Scheduled clean-up (opt-in).** Off unless `SWARMWATCH_CLEAN_SCHEDULE` is set. It removes unused images and stopped containers older than the keep window, on the manager only, never with `-f`, never volumes. There is no endpoint and no button for it, so nothing on the network can start it.
- **Image check.** `POST /api/v1/images/check` asks the registries whether tags have a new image. It does not roll, delete or restart anything. One check runs at a time; a second request while one is running does not start another. The page button sits next to scan now and cannot be pressed while a check is running. It only accepts same-origin POSTs. The API needs the token when one is set, including when the pages are off.
- **Updating (opt-in).** Off by default. With `--allow-update` anyone who can reach the UI can make swarmwatch roll a service whose image is outdated to the newest image behind its tag; with `--update-schedule` it does so by itself. A new image can break a service: a failed update is rolled back, but a "successful" one is not judged. Use `swarmwatch.update=false` for services that must not move on their own. Only the same-origin check protects the button.
- **Network exposure.** Since 0.3.0 the stack publishes no port unless you add `swarmwatch.publish.yml`. Without
  it only containers on the `swarmwatch_net` overlay network can reach it. Anything you attach to that network
  can talk to swarmwatch, so attach only what you trust with the data below.
- **API token (optional, recommended).** Set `SWARMWATCH_TOKEN_FILE` (a Docker secret, see `swarmwatch.token.yml`)
  or `SWARMWATCH_TOKEN` (visible to anyone who can inspect the service, so prefer the secret). Every request under
  `/api/` then needs `Authorization: Bearer <token>`. The token must have at least 16 characters; generate one with
  `openssl rand -hex 32`. It is compared in constant time on digests, never logged, and rejected requests are logged
  at most once a minute. There is no rate limit and no lockout, so rely on a long random token, not a short one.
  `/healthz` needs no token and shows nothing but `ok` or `stale`. The token travels in clear text over plain
  `http`; keep it on the overlay network or put TLS in front.
- **No login on the web pages.** The pages and the opt-in clean-up and update buttons have none and the token does not cover
  them. Keep the port on a trusted network, put it behind an authenticating reverse proxy, or turn the pages off
  with `SWARMWATCH_DISABLE_UI=1`. Do not expose it to the internet.
- **Browser protections.** Pages and API send a strict `Content-Security-Policy` (no scripts, no outside loads),
  `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff` and `Referrer-Policy: same-origin`. The clean-up,
  update and scan forms only accept same-origin POSTs. **Scan now** does not change the swarm; it does start Trivy,
  which uses a core or more until the scan finishes. One scan runs at a time. Anyone who can open the pages can
  press it, so keep them on a trusted network, the same as the rest of the UI.
- **SSH mode.** The CLI/config-file mode runs read-only commands on managers over `ssh` using your
  existing keys and `ssh_config`.
- **Output sensitivity.** Service names, images, published ports, host names, IPs and vulnerability data
  are shown in the UI and API. Treat them as internal information.

## Supported versions

Only the latest release and `main` receive fixes.
