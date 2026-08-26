# ngtcp2 + its GnuTLS crypto binding — the QUIC NAT-T transport.
#
# Only included when ENABLE_QUIC is true, i.e. the user explicitly asked for
# QUIC. Unlike libutp there is no bundled copy and no USE_SYSTEM_* switch:
# vendoring a QUIC implementation is a rejected alternative in this change's
# design, because QUIC is security-relevant code with an active vulnerability
# history and vendoring shifts patch responsibility onto the aMule maintainers
# indefinitely. The system package is the only route, deliberately.
#
# Three packages, all discovered through pkg-config because that is what
# ngtcp2 ships and it is the only mechanism that reports the version:
#
#   libngtcp2                 the QUIC implementation
#   libngtcp2_crypto_gnutls   its GnuTLS binding
#   gnutls                    the TLS stack itself
#
# GnuTLS rather than OpenSSL is not a preference. eMuleAI builds the same
# pairing (CNgTcp2GnuTlsBridge), so interoperability is tested against the
# implementation this transport exists to interoperate with; and Debian — the
# distribution the runtime image ships from — packages only the GnuTLS binding
# and not the OpenSSL one, so on that platform it is the only choice that does
# not mean building ngtcp2 from source. See the platform table in
# openspec/changes/amule-quic-transport/design.md.
#
# This file publishes one target, Quic::Ngtcp2, carrying the include
# directories and libraries of all three. Call sites link that and know nothing
# about the package names.

find_package (PkgConfig REQUIRED)

# The minimum is 1.0.0, and the bound is load-bearing rather than cautious.
# ngtcp2 changed its API extensively before 1.0 and distributions still carry
# pre-1.0 releases -- Ubuntu 22.04, which the dev/baseline image is built on,
# ships 0.1.0. A build against one of those does not fail at configure time
# with a version message, it fails with a wall of unresolved symbols and
# changed struct layouts, which is a far worse way to learn the same fact.
set (NGTCP2_MINIMUM_VERSION 1.0.0)

pkg_check_modules (NGTCP2 QUIET libngtcp2>=${NGTCP2_MINIMUM_VERSION})
pkg_check_modules (NGTCP2_CRYPTO_GNUTLS QUIET libngtcp2_crypto_gnutls>=${NGTCP2_MINIMUM_VERSION})
pkg_check_modules (GNUTLS QUIET gnutls)

# Honour the user's intent and fail loudly rather than silently downgrading to
# ENABLE_QUIC=NO, which would produce a green build with the transport
# mysteriously absent at runtime — the same reasoning as the ENABLE_UPNP branch
# in cmake/upnp.cmake and the ENABLE_UTP branches in cmake/libutp.cmake.
#
# The three are reported separately because they fail for different reasons and
# have different fixes. In particular "ngtcp2 is present but its GnuTLS binding
# is not" is the exact shape of the macOS situation: Homebrew's libngtcp2 links
# openssl@3 and packages no GnuTLS-bound build, so that message is the one a
# macOS user will actually see and it needs to say what to do about it.
if (NOT NGTCP2_FOUND)
	message (FATAL_ERROR "ENABLE_QUIC=YES but libngtcp2 >= ${NGTCP2_MINIMUM_VERSION} was not "
		"found by pkg-config. Install it (Debian/Ubuntu: libngtcp2-dev; MSYS2: "
		"mingw-w64-*-ngtcp2), or pass -DENABLE_QUIC=NO to build without the QUIC "
		"transport. Distributions carrying a pre-1.0 ngtcp2 -- Ubuntu 22.04 ships "
		"0.1.0 -- are not usable: the API changed extensively before 1.0.")
endif()

if (NOT NGTCP2_CRYPTO_GNUTLS_FOUND)
	message (FATAL_ERROR "ENABLE_QUIC=YES but libngtcp2_crypto_gnutls >= "
		"${NGTCP2_MINIMUM_VERSION} was not found by pkg-config. aMule's QUIC "
		"transport uses ngtcp2's GnuTLS binding, matching eMuleAI. Install it "
		"(Debian/Ubuntu: libngtcp2-crypto-gnutls-dev), or pass -DENABLE_QUIC=NO. "
		"On macOS, Homebrew's libngtcp2 links openssl@3 and no GnuTLS-bound build "
		"is packaged, so -DENABLE_QUIC=NO is the supported configuration there; "
		"the client reaches peers over uTP instead.")
endif()

if (NOT GNUTLS_FOUND)
	message (FATAL_ERROR "ENABLE_QUIC=YES but gnutls was not found by pkg-config. Install it "
		"(Debian/Ubuntu: libgnutls28-dev), or pass -DENABLE_QUIC=NO to build "
		"without the QUIC transport.")
endif()

# An INTERFACE target rather than three IMPORTED ones: nothing here needs a
# library path of its own, and pkg-config has already resolved the link lines.
add_library (amule_ngtcp2 INTERFACE)

# Deliberately not SYSTEM. No other dependency in this tree is discovered that
# way, and marking these headers system-provided would silence exactly the
# -Werror=deprecated gate that src/CMakeLists.txt sets up -- the project's
# convention is to wrap a noisy third-party include in a diagnostic pragma at
# the one place that includes it, so that the suppression is visible in the
# source rather than invisible in the build system.
target_include_directories (amule_ngtcp2 INTERFACE
	${NGTCP2_INCLUDE_DIRS}
	${NGTCP2_CRYPTO_GNUTLS_INCLUDE_DIRS}
	${GNUTLS_INCLUDE_DIRS}
)

target_link_libraries (amule_ngtcp2 INTERFACE
	${NGTCP2_LIBRARIES}
	${NGTCP2_CRYPTO_GNUTLS_LIBRARIES}
	${GNUTLS_LIBRARIES}
)

target_link_directories (amule_ngtcp2 INTERFACE
	${NGTCP2_LIBRARY_DIRS}
	${NGTCP2_CRYPTO_GNUTLS_LIBRARY_DIRS}
	${GNUTLS_LIBRARY_DIRS}
)

add_library (Quic::Ngtcp2 ALIAS amule_ngtcp2)

set (NGTCP2_VERSION_SUMMARY "${NGTCP2_VERSION} (crypto_gnutls ${NGTCP2_CRYPTO_GNUTLS_VERSION}, gnutls ${GNUTLS_VERSION})")
