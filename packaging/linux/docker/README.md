# aMule runtime image (eMuleAI network-parity fork)

A container running the aMule daemon with the modern **amuleapi** REST/SSE web
UI (and legacy **amuleweb** on demand), built from **this** tree — so it carries
the eMuleAI network-parity work that upstream and the stock image do not:
peer-capability recognition, Kad protocol `0x0a`, IPv6 dual-stack ed2k, and the
uTP transport (`ENABLE_UTP=YES`, bundled libutp).

Two tags are published: `latest`, without the QUIC NAT-T transport, and `test`,
with it — and the QUIC path is **unvalidated on the wire**. See
[The two published variants](#the-two-published-variants-latest-and-test).

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

## The two published variants: `latest` and `test`

One Dockerfile builds both, selected by the `ENABLE_QUIC` build arg. They come
out of the same run and the same checkout, so they are always the same source.

| Tag | QUIC NAT-T | Immutable tags |
| --- | --- | --- |
| `latest` | **compiled out** | `v<version>`, `sha-<commit>` |
| `test` | compiled in (`-DENABLE_QUIC=YES`) | `v<version>-quic`, `sha-<commit>-quic` |

`latest` is deliberately conservative: no ngtcp2, no GnuTLS, no QUIC code in the
binary. Nothing about it changed when `test` was added — the QUIC build-deps and
the QUIC runtime libraries are installed only when the arg is on, and with it off
the `cmake` line does not carry `-DENABLE_QUIC` at all.

To build the QUIC variant yourself:

```sh
docker build -f packaging/linux/docker/Dockerfile   --build-arg ENABLE_QUIC=YES -t amule-emuleai:test-quic .
```

The QUIC dependencies (`libngtcp2-dev`, `libngtcp2-crypto-gnutls-dev`,
`libgnutls28-dev`) are packaged in Debian trixie — the image base — for both
`linux/amd64` and `linux/arm64`, so the multi-arch build needs no
per-architecture exception. The GnuTLS binding rather than the OpenSSL one,
because trixie packages no `libngtcp2-crypto-ossl-dev`; see
`openspec/changes/amule-quic-transport/design.md`.

### `test` is unvalidated code — read this before pulling it

The QUIC transport in `test` **has never been observed working against another
implementation.** Task 4.4 of the `amule-quic-transport` change is still open,
and it is open on the QUIC half specifically:

* No QUIC connection has ever been seen completing with any peer — not with
  eMuleAI, not between two aMule instances. The ed2k half of the interop
  (capability tags, the peer identity tag `0xBF`, an ed2k handshake over native
  IPv6) is confirmed in both directions; the QUIC half is not reached.
* A real QUIC Initial offering `ed2k-ai-natt-quic-v1` was sent to a running
  eMuleAI and drew no reply — but so did both controls, so that run distinguishes
  nothing. It is consistent with that build emitting no UDP at all, and no
  positive control for its UDP receive path was available.
* One design decision inside the proof is an unresolved **50/50**:
  `kQuicProofValueDirection`, i.e. which side's advertised value goes in the
  second field of the proof record. Settling it requires an eMuleAI whose QUIC
  endpoint answers a datagram. If the guess is wrong, proof validation fails
  against eMuleAI and the code has to change.

So `test` exists to make that experiment cheap to run — two instances built with
QUIC on, on opposite sides of a NAT — not because the transport is known to
work. Anyone pulling `test` is pulling unvalidated code. Use `latest` for
anything you care about.

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
