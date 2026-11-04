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
- **No authentication.** The web UI and JSON API have none. Keep the port on a trusted network or put it
  behind an authenticating reverse proxy. Do not expose it to the internet.
- **SSH mode.** The CLI/config-file mode runs read-only commands on managers over `ssh` using your
  existing keys and `ssh_config`.
- **Output sensitivity.** Service names, images, published ports, host names, IPs and vulnerability data
  are shown in the UI and API. Treat them as internal information.

## Supported versions

Only the latest release and `main` receive fixes.
