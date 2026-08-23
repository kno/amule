# libutp — the uTP (Micro Transport Protocol) reference implementation.
#
# Only included when ENABLE_UTP is true, i.e. the user explicitly asked for the
# uTP transport. Two routes, selected by USE_SYSTEM_LIBUTP, following the same
# bundled-or-system convention as picojson (USE_SYSTEM_PICOJSON):
#
#   OFF (default) — a bundled copy under src/extern/libutp.
#   ON            — a system-installed libutp (headers + library).
#
# Either way this file publishes one imported/aliased target, Utp::Utp, and
# defines AMULE_UTP_TRANSPORT for the core targets that link it. Every uTP call
# site is behind that macro: the transport shim itself (src/Utp*.h) is pure
# logic and compiles with or without the library, and only the thin adapter
# that calls utp_* enters the picture when the macro is defined. That is what
# keeps "aMule built without libutp" a build with no uTP rather than a build
# that fails to compile.

set (LIBUTP_BUNDLED_DIR ${CMAKE_SOURCE_DIR}/src/extern/libutp)

if (USE_SYSTEM_LIBUTP)
	find_path (LIBUTP_INCLUDE_DIR
		NAMES libutp/utp.h utp.h
		PATH_SUFFIXES include
	)
	find_library (LIBUTP_LIBRARY
		NAMES utp libutp
	)

	if (NOT LIBUTP_INCLUDE_DIR OR NOT LIBUTP_LIBRARY)
		# Honour the user's intent and fail loudly rather than silently
		# downgrading to ENABLE_UTP=NO, which would produce a green build
		# with the transport mysteriously absent at runtime — the same
		# reasoning as the ENABLE_UPNP branch in cmake/upnp.cmake.
		message (FATAL_ERROR "ENABLE_UTP=YES with USE_SYSTEM_LIBUTP=YES but libutp was not "
			"found. Install libutp headers + library, or pass "
			"-DUSE_SYSTEM_LIBUTP=NO to use a bundled copy in "
			"${LIBUTP_BUNDLED_DIR}, or pass -DENABLE_UTP=NO to build without "
			"the uTP transport.")
	endif()

	add_library (Utp::Utp UNKNOWN IMPORTED)
	set_target_properties (Utp::Utp PROPERTIES
		IMPORTED_LOCATION "${LIBUTP_LIBRARY}"
		INTERFACE_INCLUDE_DIRECTORIES "${LIBUTP_INCLUDE_DIR}"
	)
	set (LIBUTP_VERSION "system (${LIBUTP_LIBRARY})")
else()
	if (NOT EXISTS ${LIBUTP_BUNDLED_DIR}/CMakeLists.txt)
		# The bundled copy normally lives in the tree -- see
		# src/extern/libutp/AMULE_PROVENANCE.md for the pinned upstream
		# commit and how to reproduce it. Say precisely which of the two
		# situations this is, because "libutp not found" and "the
		# vendored copy is missing from this checkout" are different
		# problems with different fixes.
		message (FATAL_ERROR "ENABLE_UTP=YES but no bundled libutp is present at "
			"${LIBUTP_BUNDLED_DIR}. Restore the vendored copy (see "
			"src/extern/libutp/AMULE_PROVENANCE.md for the pinned upstream "
			"commit), or pass -DUSE_SYSTEM_LIBUTP=YES to link a "
			"system-installed one, or pass -DENABLE_UTP=NO to build without "
			"the uTP transport.")
	endif()

	add_subdirectory (${LIBUTP_BUNDLED_DIR} ${CMAKE_BINARY_DIR}/src/extern/libutp EXCLUDE_FROM_ALL)

	# Upstream names the target libutp -- add_library(libutp ...) with
	# OUTPUT_NAME utp, so the artefact is libutp.a but the target is not
	# called "utp". We adapt to upstream rather than patching the vendored
	# CMakeLists.txt: a patched third-party file makes every version bump a
	# merge and makes the provenance note a lie.
	if (NOT TARGET libutp)
		message (FATAL_ERROR "The bundled libutp in ${LIBUTP_BUNDLED_DIR} did not define a "
			"target named libutp. If a version bump renamed it, adapt this "
			"file rather than the vendored sources.")
	endif()

	# Call sites link Utp::Utp and know nothing about the upstream name.
	add_library (Utp::Utp ALIAS libutp)
	set (LIBUTP_VERSION "bundled (${LIBUTP_BUNDLED_DIR})")
endif()
