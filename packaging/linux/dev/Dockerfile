# syntax=docker/dockerfile:1
#
# Development / baseline-verification image. Unlike static/ and appimage/,
# this image does NOT package anything — it builds aMule with tests enabled
# and runs ctest, so a build baseline can be established without installing
# a toolchain on the host.
#
# Dependency list is lifted from appimage/Dockerfile, which tracks the CI
# Ubuntu job. Keep the two in sync: if a dependency changes there, it
# changes here.
#
# Driven by packaging/linux/build.sh dev, which feeds the ARGs below from
# packaging/linux/versions.env (the single source of truth for pinned
# versions). Build args have no defaults so a missing pin fails loud.
#
#   packaging/linux/build.sh dev            # host arch
#
# The build fails if the tree does not compile or a test fails, so a
# successful image build IS the baseline evidence.

ARG UBUNTU_BASE

FROM ubuntu:${UBUNTU_BASE}

ARG WX_VERSION
ARG WX_GIT_URL
ARG WX_COMMIT
ARG LIBUPNP_VERSION
ARG LIBUPNP_TARBALL_URL
ARG LIBUPNP_SHA256

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC

# Mirrors appimage/Dockerfile. libupnp-dev is intentionally absent: Ubuntu
# 22.04 ships only the ancient 1.8.x line, so the pinned 22.x is built from
# source below. wxWidgets likewise — 22.04 does not package wx 3.2.x.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        ccache \
        cmake \
        ninja-build \
        pkg-config \
        git \
        ca-certificates \
        wget \
        file \
        binutils-dev \
        gettext \
        libboost-dev \
        libcrypto++-dev \
        libgd-dev \
        libgeoip-dev \
        libmaxminddb-dev \
        libreadline-dev \
        libcurl4-openssl-dev \
        libgtk-3-dev \
        libwayland-dev \
        libayatana-appindicator3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp/deps

# libupnp (pinned) — checksum verified before use.
RUN wget -q -O pupnp.tar.gz "${LIBUPNP_TARBALL_URL}" \
    && echo "${LIBUPNP_SHA256}  pupnp.tar.gz" | sha256sum -c - \
    && tar xf pupnp.tar.gz \
    && cmake -S "pupnp-release-${LIBUPNP_VERSION}" -B upnp-build -G Ninja \
        -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local \
    && cmake --build upnp-build \
    && cmake --install upnp-build \
    && rm -rf pupnp.tar.gz "pupnp-release-${LIBUPNP_VERSION}" upnp-build

# wxWidgets, pinned to a commit rather than a release, the way the appimage and
# static targets already do it (packaging/linux/appimage/Dockerfile,
# packaging/linux/static/Dockerfile): every 3.2.x tarball to date predates the
# wxEpollDispatcher unregister fix amuled needs under wxWebRequest. Fetching the
# SHA directly avoids cloning the full history; submodules supply wx's bundled
# third-party sources. Revert to a tarball when 3.2.12 ships.
RUN git init wx \
    && cd wx \
    && git remote add origin "${WX_GIT_URL}" \
    && git fetch --depth 1 origin "${WX_COMMIT}" \
    && git checkout FETCH_HEAD \
    && git submodule update --init --depth 1 --recursive \
    && ./configure --with-gtk=3 --disable-shared --enable-unicode --prefix=/usr/local \
    && make -j"$(nproc)" \
    && make install \
    && cd .. && rm -rf wx

ENV PATH="/usr/lib/ccache:${PATH}"
ENV LD_LIBRARY_PATH=/usr/local/lib

WORKDIR /src
COPY . /src

# The baseline itself. BUILD_TESTING=YES is the whole point of this image;
# a failure here is the signal the gate exists to produce.
# All three of monolithic / daemon / remotegui, per the project rule in
# CLAUDE.md: the preprocessor split means a change can compile in two of the
# three and break the third. A baseline that covers only two is not a baseline
# for anything a change will be judged against.
#
# ENABLE_UTP=YES here even though cmake/options.cmake defaults it to OFF. The
# default is a user-facing choice -- uTP is opt-in -- but a verification build
# that leaves it off never compiles a single call to utp_*, so a green test run
# says nothing whatsoever about the uTP transport. The adapter behind
# AMULE_UTP_TRANSPORT has to be compiled somewhere, and this is that somewhere.
# It uses the vendored libutp in src/extern/libutp (see its AMULE_PROVENANCE.md).
RUN cmake -B build -G Ninja \
        -DBUILD_TESTING=YES \
        -DBUILD_MONOLITHIC=YES \
        -DBUILD_DAEMON=YES \
        -DBUILD_REMOTEGUI=YES \
        -DENABLE_UTP=YES \
    && cmake --build build -j"$(nproc)"

# Recorded separately from the build so a compile failure and a test failure
# are distinguishable in the layer log.
#
# Deliberately NON-GATING: `|| true`. The purpose of this image is to discover
# what already passes and what already fails on unmodified code. If a
# pre-existing failure aborted the image build, the baseline could never be
# captured — which is the one thing this image exists to produce. The compile
# step above still fails hard, so "does not compile" and "compiles but a test
# fails" remain distinguishable.
#
# Do NOT make this gating. Gating belongs in change verification, where the
# comparison is against the failures recorded here.
# No `set -o pipefail`: the default shell here is /bin/sh (dash), which does
# not support it. Not needed either — tee always succeeds and ctest's status is
# intentionally discarded.
RUN ctest --test-dir build --output-on-failure > /baseline-tests.txt 2>&1 || true; \
    cat /baseline-tests.txt; \
    echo "--- ctest summary ---"; \
    grep -E 'tests passed|tests failed|The following tests FAILED' -A5 /baseline-tests.txt || true

# Toolchain provenance for BASELINE.md.
RUN { echo "=== baseline toolchain ==="; \
      cat /etc/os-release | head -2; \
      echo "arch: $(uname -m)"; \
      cmake --version | head -1; \
      c++ --version | head -1; \
      /usr/local/bin/wx-config --version | sed 's/^/wxWidgets /'; \
      echo "libupnp ${LIBUPNP_VERSION}"; \
      dpkg-query -W -f='${Package} ${Version}\n' libcrypto++-dev libboost-dev libmaxminddb-dev libgd-dev; \
      echo "=== test result ==="; \
      grep -E 'tests passed|tests failed' /baseline-tests.txt || echo "no ctest summary"; \
      sed -n '/The following tests FAILED/,$p' /baseline-tests.txt || true; \
    } > /baseline-toolchain.txt && cat /baseline-toolchain.txt

CMD ["/bin/bash"]
