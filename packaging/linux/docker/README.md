# aMule runtime image (eMuleAI network-parity fork)

A container running the aMule daemon with the modern **amuleapi** REST/SSE web
UI (and legacy **amuleweb** on demand), built from **this** tree — so it carries
the eMuleAI network-parity work that upstream and the stock image do not:
peer-capability recognition, Kad protocol `0x0a`, IPv6 dual-stack ed2k, and the
uTP transport (`ENABLE_UTP=YES`, bundled libutp).

## Attribution

The operational layer — `docker/entrypoint.sh`, `docker/amule-config.sh`,
`docker/amule-mods.sh`, the s6 `services.d/` tree, the env-var contract, and the
minimal-ffprobe build in the `Dockerfile` — is derived from
[**ngosang/docker-amule**](https://github.com/ngosang/docker-amule) (MIT,
Copyright (c) 2021 Diego Heras). Its licence is kept verbatim in
`LICENSE.ngosang-docker-amule`. The substantive change here is the aMule build
stage: it compiles the local source tree with the uTP transport enabled instead
of fetching an upstream release.

aMule itself is GPL-2.0-or-later; the published image is tagged with the source
commit so the corresponding source is always identifiable.

## Build

From the repository root (the build context must be the root — the Dockerfile
`COPY`s the source tree):

```sh
docker build -f packaging/linux/docker/Dockerfile -t amule-emuleai:local .
```

Multi-arch, as the CI does:

```sh
docker buildx build -f packaging/linux/docker/Dockerfile \
  --platform linux/amd64,linux/arm64 -t <registry>/amule-emuleai:test .
```

CI publishes to `ghcr.io/<owner>/amule-emuleai` on pushes to `master` and on
`v*` tags — see `.github/workflows/docker-runtime.yml`.

## Run

```sh
docker run -d --name amule \
  -e GUI_PWD=change-me-ec \
  -e WEBUI_PWD=change-me-web \
  -e PUID=1000 -e PGID=1000 -e TZ=Europe/Madrid \
  -p 4711:4711 -p 4662:4662 -p 4672:4672/udp \
  -v /my/amule/config:/home/amule/.aMule \
  -v /my/downloads:/downloads \
  <registry>/amule-emuleai:latest
```

Web UI at `http://<host>:4711` — log in as **admin** with `WEBUI_PWD`.

### Key environment variables

Same contract as ngosang/docker-amule:

| Variable | Default | Purpose |
| --- | --- | --- |
| `GUI_PWD` | random | External Connections password (amuleapi ↔ amuled) |
| `WEBUI_PWD` | random | Web UI admin password |
| `WEBUI_GUEST_PWD` | (off) | Read-only guest account |
| `PUID` / `PGID` | 1000 | User/group the daemon runs as |
| `UMASK` | 0002 | File-creation mask |
| `TZ` | Europe/London | Timezone |
| `LEGACY_AMULEWEB_ENABLED` | false | Serve the old amuleweb instead of amuleapi |
| `TEMP_DIR` / `INCOMING_DIR` | /downloads/temp, /downloads/incoming | Download paths |

If a password env var is unset a random one is generated and printed to the
container log on first start.

### Ports

| Port | Purpose |
| --- | --- |
| 4711/tcp | Web UI + REST API (amuleapi) |
| 4712/tcp | External Connections (amulecmd / amulegui) |
| 4662/tcp | ed2k client-to-client |
| 4665/udp | ed2k server UDP |
| 4672/udp | extended eMule + Kad UDP |

## IPv6

The **binary** supports IPv6: `amuled` binds `::` and accepts inbound IPv6 ed2k
connections (this is the network-parity work). But a container only *reaches*
IPv6 if the **container network** provides it — that is the operator's Docker
daemon setting, not something the image can switch on.

Enable it on the host, then the daemon's `::` bind is reachable end to end:

```sh
# one-off network with a routable/ULA v6 prefix
docker network create --ipv6 --subnet 2001:db8:1::/64 amule6
docker run ... --network amule6 <registry>/amule-emuleai:latest
```

For globally-routable inbound IPv6 (so peers can reach you without a HighID),
the host itself needs native IPv6 and the Docker daemon must be configured for
it (`"ipv6": true` plus an `ip6tables`/prefix setup in `/etc/docker/daemon.json`).
Without that, IPv6 works only between containers on the v6 network.
