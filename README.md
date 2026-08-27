# aMule — eMuleAI network-parity fork

![aMule](https://raw.githubusercontent.com/amule-org/amule/master/org.amule.aMule.svg)

aMule is an eMule-like client for the eDonkey and Kademlia networks.

**This is a fork of [amule-org/amule](https://github.com/amule-org/amule)**, not
upstream aMule. It carries aMule 3.0.1 plus the wire-level extensions an
**eMuleAI** peer expects, so the two implementations recognise each other's
capabilities instead of falling back to the plain eD2k subset: peer capability
negotiation, Kademlia protocol `0x0a`, family-agnostic addressing, IPv6 dual
stack, the uTP transport, and NAT traversal. A QUIC NAT-T transport is present
but **unvalidated on the wire** — see the release notes before relying on it.

Everything else — the client, its features, its documentation — is upstream
aMule's work. Bug reports for this fork's changes belong here; anything else
belongs [upstream](https://github.com/amule-org/amule/issues).

[Forum] | [Documentation] | [FAQ]

[Forum]:         https://github.com/amule-org/amule/discussions "aMule Forum"
[Documentation]: https://amule-org.github.io/docs "aMule Documentation"
[FAQ]:           https://amule-org.github.io/docs/manual/faq "FAQ on aMule"

## Where things live

| | |
| --- | --- |
| **Releases and binaries of this fork** | [kno/amule/releases](https://github.com/kno/amule/releases/latest) |
| **Container images of this fork** | [ghcr.io/kno/amule-emuleai](https://github.com/users/kno/packages/container/package/amule-emuleai) |
| **Issues about this fork's changes** | [kno/amule/issues](https://github.com/kno/amule/issues) |
| Upstream aMule | [amule-org/amule](https://github.com/amule-org/amule) |
| Upstream documentation, FAQ and forum | linked throughout this file |

Distribution packages named `amule` are **upstream aMule**, not this fork, and
they lag badly: Debian 13 still ships 2.3.3 (2021), five years behind the 3.0.1
this tree is built on. Use the releases or the container image above.

## Overview

aMule is a multi-platform client for the eD2k / Kad file-sharing network,
originally a fork of the Windows client eMule (via xMule and lMule).
aMule started in August 2003.

Supported platforms today: Linux, FreeBSD, OpenBSD, NetBSD, macOS, and
Windows (MSYS2 / mingw-w64), on both x86_64 and ARM64.

aMule aims to stay close to eMule in look-and-feel so users moving between
the two have minimal friction. New eMule protocol-level features are
generally adopted into aMule shortly after.

---

## Development Statistics

| [kno/amule](https://github.com/kno/amule) (this fork) |
| --- |
| [![Open Pull Requests](https://img.shields.io/github/issues-pr/kno/amule)](https://github.com/kno/amule/pulls) |
| [![Open Issues](https://img.shields.io/github/issues/kno/amule)](https://github.com/kno/amule/issues) |
| [![Latest release](https://img.shields.io/github/v/release/kno/amule?include_prereleases)](https://github.com/kno/amule/releases/latest) |

Upstream's own counters live at
[amule-org/amule](https://github.com/amule-org/amule).

## Features

* `amule` — all-in-one GUI client.
* `amuled` — headless daemon, no GUI.
* `amulegui` — remote GUI; connects to a local or remote `amuled` over the
  EC (External Connection) protocol.
* `amuleweb` — HTTP interface to a running `amuled`.
* `amulecmd` — interactive CLI for a running `amuled`.
* `amuleapi` — REST API for a running `amuled`.

## Installation

aMule ships pre-built binaries for every major desktop system. Building from
source is also supported.

### Pre-built binaries (recommended)

Download the latest release for your platform from the
[Releases page]. Quick start:

* **Linux**
  * Flatpak: `flatpak install ./appname.flatpak`
  * AppImage: `chmod +x` and run
* **macOS** — Universal2 `.dmg`: download, drag to `/Applications`.
* **Windows** — choose either the **NSIS installer** `.exe` (Start-menu shortcuts, uninstaller, x64 / ARM64) or the **portable `.zip`** (no install, unzip and run).

### Container image

A runtime image of this fork (daemon + `amuleapi` + `amuleweb` + `amulecmd`) is
published on every push to `master`:

```sh
docker pull ghcr.io/kno/amule-emuleai:latest    # QUIC compiled in
docker pull ghcr.io/kno/amule-emuleai:noquic    # QUIC compiled out
```

Both variants are built from one checkout in one workflow run, so they can never
come from different source, and switching between them is one line in a compose
file. Version-pinned tags (`:3.0.1-emuleai.1`) and commit-pinned tags
(`:sha-<commit>`) are published alongside, so a running binary always maps back
to its exact GPL source revision.

See [packaging/linux/docker/README.md](packaging/linux/docker/README.md) for the
environment-variable contract, port list, IPv6 notes, and the warning about what
the QUIC path has and has not been validated to do.

See [docs/INSTALL_BINARIES.md](docs/INSTALL_BINARIES.md) for
per-platform notes — including the macOS unsigned-binary
workaround, the Windows SmartScreen prompt, and the Linux FUSE
dependency for AppImage.

[Releases page]: https://github.com/kno/amule/releases/latest

### Building from source

aMule uses CMake. Quick start:

```sh
cmake -B build -DBUILD_MONOLITHIC=YES -DBUILD_REMOTEGUI=YES
cmake --build build -j"$(nproc)"
sudo cmake --install build
```

See [docs/INSTALL.md](docs/INSTALL.md) for the full list of dependencies,
build options (`BUILD_DAEMON`, `BUILD_AMULECMD`, `ENABLE_NLS`, `ENABLE_UPNP`,
`ENABLE_IP2COUNTRY`, etc.), and platform-specific notes. The CI workflow
[`.github/workflows/ccpp.yml`](.github/workflows/ccpp.yml) is the
authoritative reference for the exact deps and flags used to build aMule
on Linux, macOS, and Windows.

## Setting Up

aMule comes with reasonable default settings and should be usable as-is.
Two configuration steps are still worth doing on day one.

### Open the ports — get a HighID

To receive a [HighID] you need to open aMule's ports on your firewall
and/or forward them on your router. See the [network connectivity
guide][network] for details.

[HighID]:  https://amule-org.github.io/docs/p2p-networks/ed2k/high-id "What is LowID and HighID?"
[network]: https://amule-org.github.io/docs/manual/configuration/network-connectivity "Network connectivity"

### Set bandwidth limits

aMule ships with both upload and download caps disabled by default
(`MaxUpload=0`, `MaxDownload=0` — both interpreted as literal
unlimited). On a connection that aMule can saturate, that means
aMule will eat all the bandwidth available to it, starving every
other application sharing the link. **Setting realistic limits is
strongly recommended.**

Under `Preferences → Connection`, set the limits to roughly **80 %
of your actual line speed** to avoid saturating the upstream and
starving your own traffic. Values are in **kibibytes per second**
(KiB/s, units of 1024 bytes); ISP advertised speeds are usually in
**megabits per second** (Mbps). To convert, multiply Mbps by **122**.

> Example: a 100 Mbps / 20 Mbps fibre line → roughly 12 200 KiB/s
> downstream and 2 440 KiB/s upstream. Set the limits to about
> 9 800 down / 1 950 up to stay below the line cap.

## Reporting Bugs

Route the report by what it is about, because the two trackers have different
owners:

* **Something this fork changed** — peer capability negotiation, Kademlia `0x0a`,
  addressing, IPv6 dual stack, uTP, NAT traversal, QUIC, or the container image:
  open it on [this fork's tracker][5].
* **Anything else in aMule** — open it [upstream][5-up], where the code and the
  people who know it live. Do not file upstream bugs here; it only delays them.

A good bug report includes the exact aMule version (`amuled --version` — a build
of this fork reports `aMule v3.0.1-emuleai.1` or similar), the platform you're
on, and steps to reproduce. See the [bug report guide][bug-report] for detailed
instructions on attaching backtraces and reproducer steps.

[5]:          https://github.com/kno/amule/issues "This fork's issues"
[5-up]:       https://github.com/amule-org/amule/issues "Upstream aMule issues"
[bug-report]: https://amule-org.github.io/docs/contributing/bug-report "Bug Report Instructions"

## Contributing

*Contributions are always welcome!*

See the [contributing guide][contributing] for how to get involved. In short:

* **Code** — fix a bug, implement a feature, improve performance. The preferred
  path is a [pull request][6] on GitHub; patches on the [forum] also work.
* **Translation** — translate aMule, its documentation, or its website into
  your language.
* **Documentation** — help improve the project documentation at
  [amule-org.github.io/docs][Documentation].

[6]:            https://github.com/amule-org/amule/pulls "aMule Pull Requests"
[contributing]: https://amule-org.github.io/docs/contributing "Contributing to aMule"

## Translations

The translations of the application interface and the man pages live in this
repository and can be edited either by opening a pull request — see the
[Translations guide](https://amule-org.github.io/docs/developer/translations) —
or through [Weblate](https://hosted.weblate.org/projects/amule/), a translation
tool that stays in sync with git — see the
[Weblate guide](https://amule-org.github.io/docs/developer/translations/weblate).
