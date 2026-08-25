# aMule runtime image — daemon + amuleapi (REST/SSE) + amuleweb + amulecmd.
#
# Derived from ngosang/docker-amule (MIT, Copyright (c) 2021 Diego Heras):
# https://github.com/ngosang/docker-amule — see LICENSE.ngosang-docker-amule.
# The operational layer (s6 services, entrypoint, amule-config.sh, the env-var
# contract, the ffprobe build) is reused verbatim. The one substantive change is
# the aMule build stage: instead of fetching an upstream release it compiles THIS
# tree — the eMuleAI network-parity fork — from the build context, and enables the
# uTP transport (ENABLE_UTP), which upstream and the ngosang image do not build.
#
# Build from the repository root:
#   docker build -f packaging/linux/docker/Dockerfile -t amule-emuleai:test .
# Multi-arch:
#   docker buildx build -f packaging/linux/docker/Dockerfile \
#     --platform linux/amd64,linux/arm64/v8 -t <registry>/amule-emuleai:test .

FROM debian:trixie-slim AS builder

ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /tmp

# Install build tools
# libatomic1: required for 32-bit targets (386, arm/v5, arm/v7)
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake make git binutils-dev ca-certificates pkg-config libatomic1 \
        libboost-dev libcrypto++-dev libmaxminddb-dev libglib2.0-dev libreadline-dev libwxgtk3.2-dev zlib1g-dev libpng-dev libupnp-dev \
    && rm -rf /var/lib/apt/lists/*

# Build a minimal ffprobe from source (~3 MB). aMule uses it to extract length, bitrate and
# codec from shared media files. The Debian ffmpeg package would add ~470 MB, so everything
# is disabled except the demuxers, parsers and the file protocol that ffprobe needs to read
# container metadata: no decoders, no encoders, no muxers, no filters, no network. ffprobe
# needs only avcodec and avformat, so avdevice, avfilter, swscale and swresample are skipped
ARG FFMPEG_REF=n9.0.1
RUN git init -q ffmpeg-src && \
    git -C ffmpeg-src fetch --depth 1 https://github.com/FFmpeg/FFmpeg.git ${FFMPEG_REF} && \
    git -C ffmpeg-src checkout -q FETCH_HEAD && \
    cd ffmpeg-src && \
    ./configure \
        --prefix=/usr \
        --disable-autodetect \
        --disable-everything \
        --disable-doc \
        --disable-debug \
        --disable-network \
        --disable-programs \
        --disable-x86asm \
        --disable-avdevice \
        --disable-avfilter \
        --disable-swscale \
        --disable-swresample \
        --enable-ffprobe \
        --enable-demuxers \
        --enable-parsers \
        --enable-protocol=file \
        --enable-zlib \
        --enable-small && \
    make -j"$(nproc)" && \
    make install && \
    strip /usr/bin/ffprobe && \
    rm -rf /tmp/*

# Build aMule from THIS tree (the eMuleAI network-parity fork).
#
# Unlike the upstream image, the source is the build context rather than a git
# fetch, so the vendored libutp under src/extern/libutp is present and the uTP
# transport is compiled in (ENABLE_UTP=YES, USE_SYSTEM_LIBUTP=NO — the bundled
# copy, no system package). Everything else mirrors the upstream image's flags.
COPY . /tmp/amule-src
RUN \
    # libatomic1 only ships libatomic.so.1; find_library(atomic) needs the unversioned symlink
    so="$(find /usr/lib -name 'libatomic.so.1' -print -quit)" && [ -n "$so" ] && ln -sf "$(basename "$so")" "${so%.1}" ; \
    cmake -B /tmp/amule-build /tmp/amule-src \
        -DCMAKE_INSTALL_PREFIX=/usr \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_TESTING=NO \
        -DBUILD_MONOLITHIC=NO \
        -DBUILD_DAEMON=YES \
        -DBUILD_AMULECMD=YES \
        -DBUILD_WEBSERVER=YES \
        -DBUILD_AMULEAPI=YES \
        -DBUILD_ALCC=YES \
        -DENABLE_UTP=YES \
        -DUSE_SYSTEM_LIBUTP=NO \
        -DENABLE_IP2COUNTRY=YES \
        -DENABLE_UPNP=YES \
        -DENABLE_NLS=NO && \
    cmake --build /tmp/amule-build -j"$(nproc)" && \
    cmake --install /tmp/amule-build && \
    rm -rf /tmp/amule-build

FROM debian:trixie-slim

ENV DEBIAN_FRONTEND=noninteractive

LABEL org.opencontainers.image.title="aMule (eMuleAI network-parity)" \
      org.opencontainers.image.description="aMule daemon with amuleapi, amuleweb and the eMuleAI network-parity work (peer capabilities, Kad 0x0a, IPv6 dual-stack, uTP). Operational layer derived from ngosang/docker-amule (MIT)." \
      org.opencontainers.image.licenses="GPL-2.0-or-later"

# Copy binaries and Web UI
COPY --from=builder /usr/bin/alcc /usr/bin/amuleapi /usr/bin/amulecmd /usr/bin/amuled /usr/bin/amuleweb /usr/bin/ed2k /usr/bin/ffprobe /usr/bin/
COPY --from=builder /usr/share/amule /usr/share/amule

# Install runtime dependencies and remove unnecessary locale files
RUN apt-get update && apt-get install -y --no-install-recommends \
        libcrypto++8t64 libreadline8t64 libgcc-s1 libstdc++6 libpng16-16t64 libwxbase3.2-1t64 libglib2.0-0t64 libupnp17t64 libmaxminddb0 \
        libatomic1 libbinutils ca-certificates curl tzdata procps pwgen s6 cron systemd-standalone-sysusers \
    && rm -rf /var/lib/apt/lists/* /usr/share/locale /usr/share/doc/* /usr/share/doc-base /usr/share/lintian && \
    # Check binaries are OK (fail the build if any shared library is missing)
    for bin in alcc amuleapi amulecmd amuled amuleweb ed2k ffprobe; do \
        if ldd "/usr/bin/$bin" | grep -q "not found"; then echo "ERROR: missing shared libraries in $bin:"; ldd "/usr/bin/$bin"; exit 1; fi; \
    done

# Use the built-in C.UTF-8 locale so amuled handles non-ASCII paths correctly
ENV LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

# Add entrypoint and S6 services (reused from ngosang/docker-amule, MIT)
COPY --chmod=755 packaging/linux/docker/docker/entrypoint.sh packaging/linux/docker/docker/amule-config.sh packaging/linux/docker/docker/amule-mods.sh /home/amule/
COPY --chmod=755 packaging/linux/docker/docker/services.d/ /etc/services.d/

WORKDIR /home/amule

EXPOSE 4711/tcp 4712/tcp 4662/tcp 4665/udp 4672/udp

ENTRYPOINT ["/home/amule/entrypoint.sh"]
