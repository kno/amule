add_executable (CTagTest
	CTagTest.cpp
	${CMAKE_SOURCE_DIR}/src/SafeFile.cpp
	${CMAKE_SOURCE_DIR}/src/MemFile.cpp
	${CMAKE_SOURCE_DIR}/src/Tag.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/Format.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/strerror_r.c
	# CNetworkAddress::FromString/ToString live in NetworkAddress.cpp: they are
	# the only part of the type that still compiles Boost.Asio, and keeping them
	# out of the header is what stops asio reaching most of src/. Every target
	# whose include closure touches NetworkAddress.h therefore has to link this
	# TU -- the type is no longer header-only.
	${CMAKE_SOURCE_DIR}/src/NetworkAddress.cpp
)

add_test (NAME CTagTest
	COMMAND CTagTest
)

target_include_directories (CTagTest
	PRIVATE ${CMAKE_BINARY_DIR}
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
	# NetworkAddress.cpp, linked above, is the one TU that still compiles
	# Boost.Asio for its address parsing and formatting.
	PRIVATE ${Boost_INCLUDE_DIR}
)

target_link_libraries (CTagTest
	muleunit
	${Boost_LIBRARIES}
)

# CValueMap is the incremental-update filter behind every EC tag that carries a
# value map. Its failure mode is silence -- a field wrongly judged unchanged
# just stops updating in the GUI -- so the contract is pinned here rather than
# left to a clean daemon run. Needs no app, no daemon and no database: the EC
# tag types and their generated codes are the whole dependency.
# How a peer's version is spelled. Each client project writes its own
# differently -- eMule letters the update (0.70b), eMule Plus omits zero
# components, lPhant counts its major one higher -- and the rendering used to
# exist twice: once in the handshake, once in the client-history rows, which
# re-derived it from the stored numeric and dropped every convention. The same
# peer could appear in one window under two versions depending only on whether
# it was online. Needs no app and no daemon.
add_executable (ClientVersionStringTest
	ClientVersionStringTest.cpp
	${CMAKE_SOURCE_DIR}/src/ClientVersionString.cpp
)

add_test (NAME ClientVersionStringTest
	COMMAND ClientVersionStringTest
)

target_include_directories (ClientVersionStringTest
	PRIVATE ${CMAKE_BINARY_DIR}
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
	PRIVATE ${CMAKE_SOURCE_DIR}/src/libs
)

target_link_libraries (ClientVersionStringTest
	muleunit
	mulecommon
)

add_executable (ECIdDiffTest
	ECIdDiffTest.cpp
	# See the note on CValueMapTest below: libec.a references DoECLogLine /
	# theLogger unconditionally in Debug, so the no-op definitions have to be
	# linked in or only the Debug matrix entries fail.
	${CMAKE_SOURCE_DIR}/src/LoggerConsole.cpp
)

add_test (NAME ECIdDiffTest
	COMMAND ECIdDiffTest
)

target_include_directories (ECIdDiffTest
	PRIVATE ${CMAKE_BINARY_DIR}
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
	PRIVATE ${CMAKE_SOURCE_DIR}/src/libs
	PRIVATE ${CMAKE_BINARY_DIR}/src/libs
	PRIVATE ${CMAKE_BINARY_DIR}/src/libs/ec/cpp
)

target_link_libraries (ECIdDiffTest
	muleunit
	ec
	mulecommon
)

# amulecmd's `progress` output. The daemon answers EC_OP_SEARCH_PROGRESS in
# three shapes and the client does not choose which: advertising the union
# capability alongside multi-search is what decides it. Reading one shape as
# another is invisible -- a top-level tag that is not there reads as zero, so
# `progress` reported 0 % for every search whatever it was doing (#1126).
# Needs no app and no daemon: the EC tag types are the whole dependency.
add_executable (SearchProgressReportTest
	SearchProgressReportTest.cpp
	${CMAKE_SOURCE_DIR}/src/SearchProgressReport.cpp
	# As for ECIdDiffTest: libec.a references DoECLogLine / theLogger
	# unconditionally in Debug, so the no-op definitions have to be linked in.
	${CMAKE_SOURCE_DIR}/src/LoggerConsole.cpp
)

add_test (NAME SearchProgressReportTest
	COMMAND SearchProgressReportTest
)

target_include_directories (SearchProgressReportTest
	PRIVATE ${CMAKE_BINARY_DIR}
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
	PRIVATE ${CMAKE_SOURCE_DIR}/src/libs
	PRIVATE ${CMAKE_BINARY_DIR}/src/libs
	PRIVATE ${CMAKE_BINARY_DIR}/src/libs/ec/cpp
)

target_link_libraries (SearchProgressReportTest
	muleunit
	ec
	mulecommon
)

add_executable (ECSocketFlagsTest
	ECSocketFlagsTest.cpp
	# As for ECIdDiffTest: libec.a references DoECLogLine / theLogger
	# unconditionally in Debug, so the no-op definitions have to be linked in.
	${CMAKE_SOURCE_DIR}/src/LoggerConsole.cpp
)

add_test (NAME ECSocketFlagsTest
	COMMAND ECSocketFlagsTest
)

target_include_directories (ECSocketFlagsTest
	PRIVATE ${CMAKE_BINARY_DIR}
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
	PRIVATE ${CMAKE_SOURCE_DIR}/src/libs
	PRIVATE ${CMAKE_BINARY_DIR}/src/libs
	PRIVATE ${CMAKE_BINARY_DIR}/src/libs/ec/cpp
)

target_link_libraries (ECSocketFlagsTest
	muleunit
	ec
	mulecommon
)

add_executable (CValueMapTest
	CValueMapTest.cpp
	# LoggerConsole.cpp provides the no-op DoECLogLine + theLogger symbols that
	# libec.a's Debug build references unconditionally (ECPacket / ECSocket /
	# ECTag debug-print paths). Release preprocesses those calls to
	# `do {} while(0)` via the ECLog.h define, so the symbols are unused there
	# and only the Debug matrix entries fail to link. Same reason RefresherTest
	# pulls this TU in.
	${CMAKE_SOURCE_DIR}/src/LoggerConsole.cpp
)

add_test (NAME CValueMapTest
	COMMAND CValueMapTest
)

target_include_directories (CValueMapTest
	PRIVATE ${CMAKE_BINARY_DIR}
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
	PRIVATE ${CMAKE_SOURCE_DIR}/src/libs
	PRIVATE ${CMAKE_BINARY_DIR}/src/libs
	PRIVATE ${CMAKE_BINARY_DIR}/src/libs/ec/cpp
)

target_link_libraries (CValueMapTest
	muleunit
	ec
	mulecommon
)

add_executable (CUInt128Test
	CUInt128Test.cpp
	${CMAKE_SOURCE_DIR}/src/kademlia/utils/UInt128.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/Format.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/strerror_r.c
)

add_test (NAME CUInt128Test
	COMMAND CUInt128Test
)

target_include_directories (CUInt128Test
	PRIVATE ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries (CUInt128Test
	muleunit
)

# The AICH-hash carriage Kad protocol version 0x09 added to keyword storage.
# CKadAICHHashList is deliberately written against a plain 20-byte array rather
# than CAICHHash, so the codec that pins TAG_KADAICHHASHRESULT's byte layout can
# be tested without dragging in SHAHashSet.cpp and the whole file machinery
# behind it.
add_executable (KadAICHHashListTest
	KadAICHHashListTest.cpp
	${CMAKE_SOURCE_DIR}/src/kademlia/kademlia/AICHHashList.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/Format.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/strerror_r.c
)

add_test (NAME KadAICHHashListTest
	COMMAND KadAICHHashListTest
)

target_include_directories (KadAICHHashListTest
	PRIVATE ${CMAKE_BINARY_DIR}
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
)

target_link_libraries (KadAICHHashListTest
	muleunit
)

# The adaptive Kad response-time ceiling. CFastKad takes "now" as a parameter
# rather than reading a clock, which is what lets the cold start, the rising and
# falling distributions and the window bound all be pinned without waiting.
add_executable (FastKadTest
	FastKadTest.cpp
	${CMAKE_SOURCE_DIR}/src/kademlia/net/FastKad.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/Format.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/strerror_r.c
)

add_test (NAME FastKadTest
	COMMAND FastKadTest
)

target_include_directories (FastKadTest
	PRIVATE ${CMAKE_BINARY_DIR}
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
)

target_link_libraries (FastKadTest
	muleunit
)

# The Kad identity protections: the one-hour identity-change interval, the
# problematic list, the per-address ban and the bounds on all three tables.
# Same reasoning as FastKad -- every entry point takes the time, so a four-hour
# ban expiry is a single call rather than an untestable wait.
add_executable (SafeKadTest
	SafeKadTest.cpp
	${CMAKE_SOURCE_DIR}/src/kademlia/net/SafeKad.cpp
	${CMAKE_SOURCE_DIR}/src/kademlia/utils/UInt128.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/Format.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/strerror_r.c
)

add_test (NAME SafeKadTest
	COMMAND SafeKadTest
)

target_include_directories (SafeKadTest
	PRIVATE ${CMAKE_BINARY_DIR}
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
)

target_link_libraries (SafeKadTest
	muleunit
)

add_executable (FileDataIOTest
	FileDataIOTest.cpp
	${CMAKE_SOURCE_DIR}/src/SafeFile.cpp
	${CMAKE_SOURCE_DIR}/src/CFile.cpp
	${CMAKE_SOURCE_DIR}/src/MemFile.cpp
	${CMAKE_SOURCE_DIR}/src/kademlia/utils/UInt128.cpp
	${CMAKE_SOURCE_DIR}/src/Tag.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/Path.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/Format.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/strerror_r.c
	# CNetworkAddress::FromString/ToString live in NetworkAddress.cpp: they are
	# the only part of the type that still compiles Boost.Asio, and keeping them
	# out of the header is what stops asio reaching most of src/. Every target
	# whose include closure touches NetworkAddress.h therefore has to link this
	# TU -- the type is no longer header-only.
	${CMAKE_SOURCE_DIR}/src/NetworkAddress.cpp
)

add_test (NAME FileDataIOTest
	COMMAND FileDataIOTest
)

target_include_directories (FileDataIOTest
	PRIVATE ${CMAKE_BINARY_DIR}
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
	# NetworkAddress.cpp, linked above, is the one TU that still compiles
	# Boost.Asio for its address parsing and formatting.
	PRIVATE ${Boost_INCLUDE_DIR}
)

target_link_libraries (FileDataIOTest
	muleunit
	${Boost_LIBRARIES}
)

add_executable (CloneFileTest
	CloneFileTest.cpp
	${CMAKE_SOURCE_DIR}/src/SafeFile.cpp
	${CMAKE_SOURCE_DIR}/src/CFile.cpp
	${CMAKE_SOURCE_DIR}/src/MemFile.cpp
	${CMAKE_SOURCE_DIR}/src/kademlia/utils/UInt128.cpp
	${CMAKE_SOURCE_DIR}/src/Tag.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/Path.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/Format.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/strerror_r.c
	# CNetworkAddress::FromString/ToString live in NetworkAddress.cpp: they are
	# the only part of the type that still compiles Boost.Asio, and keeping them
	# out of the header is what stops asio reaching most of src/. Every target
	# whose include closure touches NetworkAddress.h therefore has to link this
	# TU -- the type is no longer header-only.
	${CMAKE_SOURCE_DIR}/src/NetworkAddress.cpp
)

add_test (NAME CloneFileTest
	COMMAND CloneFileTest
)

target_include_directories (CloneFileTest
	PRIVATE ${CMAKE_BINARY_DIR}
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
	# NetworkAddress.cpp, linked above, is the one TU that still compiles
	# Boost.Asio for its address parsing and formatting.
	PRIVATE ${Boost_INCLUDE_DIR}
)

target_link_libraries (CloneFileTest
	muleunit
	${Boost_LIBRARIES}
)

add_executable (FormatTest
	FormatTest.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/Format.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/strerror_r.c
)

add_test (NAME FormatTest
	COMMAND FormatTest
)

target_include_directories (FormatTest
	PRIVATE ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries (FormatTest
	muleunit
)

add_executable (NetworkFunctionsTest
	NetworkFunctionsTest.cpp
	${CMAKE_SOURCE_DIR}/src/NetworkFunctions.cpp
	${CMAKE_SOURCE_DIR}/src/LibSocket.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/Format.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/strerror_r.c
	# CNetworkAddress::FromString/ToString live in NetworkAddress.cpp: they are
	# the only part of the type that still compiles Boost.Asio, and keeping them
	# out of the header is what stops asio reaching most of src/. Every target
	# that touches an address therefore has to link this TU -- the type is no
	# longer header-only.
	${CMAKE_SOURCE_DIR}/src/NetworkAddress.cpp
)

add_test (NAME NetworkFunctionsTest
	COMMAND NetworkFunctionsTest
)

target_compile_definitions (NetworkFunctionsTest
	PRIVATE "EC_REMOTE"
)

target_include_directories (NetworkFunctionsTest
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
)

target_include_directories (NetworkFunctionsTest
	PRIVATE ${Boost_INCLUDE_DIR}
)

target_link_libraries (NetworkFunctionsTest
	${Boost_LIBRARIES}
)

target_link_libraries (NetworkFunctionsTest
	muleunit
	wxWidgets::NET
)

if (WIN32)
	# This test compiles LibSocket.cpp directly (not via the mulesocket
	# library), so it needs iphlpapi for GetAdaptersAddresses() itself.
	target_link_libraries (NetworkFunctionsTest iphlpapi)
endif()

add_executable (PathTest
	PathTest.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/Format.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/strerror_r.c
	${CMAKE_SOURCE_DIR}/src/libs/common/Path.cpp
)

add_test (NAME PathTest
	COMMAND PathTest
)

target_link_libraries (PathTest
	muleunit
)

add_executable (RangeMapTest
	RangeMapTest.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/Format.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/strerror_r.c
)

add_test (NAME RangeMapTest
	COMMAND RangeMapTest
)

target_include_directories (RangeMapTest
	PRIVATE ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries (RangeMapTest
	muleunit
)

add_executable (StringFunctionsTest
	StringFunctionsTest.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/Format.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/strerror_r.c
	${CMAKE_SOURCE_DIR}/src/libs/common/Path.cpp
)

add_test (NAME StringFunctionsTest
	COMMAND StringFunctionsTest
)

target_link_libraries (StringFunctionsTest
	muleunit
)

add_executable (PhpArrayTest
	PhpArrayTest.cpp
	${CMAKE_SOURCE_DIR}/src/webserver/src/php_syntree.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/Format.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/strerror_r.c
)

add_test (NAME PhpArrayTest
	COMMAND PhpArrayTest
)

target_compile_definitions (PhpArrayTest
	PRIVATE PHP_STANDALONE_EN
)

target_include_directories (PhpArrayTest
	PRIVATE ${CMAKE_SOURCE_DIR}/src/webserver/src
)

target_link_libraries (PhpArrayTest
	muleunit
)

add_executable (CMuleCollectionTest
	CMuleCollectionTest.cpp
	${CMAKE_SOURCE_DIR}/src/MuleCollection.cpp
	# muleunit's MuleDebug.cpp needs CFormat for its backtrace path, which
	# is compiled in on glibc; without these the link fails on Linux while
	# passing on macOS.
	${CMAKE_SOURCE_DIR}/src/libs/common/Format.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/strerror_r.c
)

add_test (NAME CMuleCollectionTest
	COMMAND CMuleCollectionTest
)

target_include_directories (CMuleCollectionTest
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
)

target_link_libraries (CMuleCollectionTest
	muleunit
)

add_executable (MagnetURITest
	MagnetURITest.cpp
	${CMAKE_SOURCE_DIR}/src/MagnetURI.cpp
	# See the CMuleCollectionTest comment above -- same Linux-backtrace need.
	${CMAKE_SOURCE_DIR}/src/libs/common/Format.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/strerror_r.c
)

add_test (NAME MagnetURITest
	COMMAND MagnetURITest
)

target_include_directories (MagnetURITest
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
)

target_link_libraries (MagnetURITest
	muleunit
)

add_executable (SearchHistoryTest
	SearchHistoryTest.cpp
	${CMAKE_SOURCE_DIR}/src/SearchHistory.cpp
	# See the CMuleCollectionTest comment above -- same Linux-backtrace need.
	${CMAKE_SOURCE_DIR}/src/libs/common/Format.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/strerror_r.c
)

add_test (NAME SearchHistoryTest
	COMMAND SearchHistoryTest
)

target_include_directories (SearchHistoryTest
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
)

target_link_libraries (SearchHistoryTest
	muleunit
)

add_executable (TextFileTest
	TextFileTest.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/Format.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/strerror_r.c
	${CMAKE_SOURCE_DIR}/src/libs/common/Path.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/TextFile.cpp
)

add_test (NAME TextFileTest
	COMMAND TextFileTest
)

target_compile_definitions (TextFileTest
	PRIVATE "SRCDIR=${CMAKE_CURRENT_SOURCE_DIR}"
)

target_include_directories (TextFileTest
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
)

target_link_libraries (TextFileTest
	muleunit
)

add_executable (OtherFunctionsTest
	OtherFunctionsTest.cpp
	${CMAKE_SOURCE_DIR}/src/OtherFunctions.cpp
	# CNetworkAddress::FromString/ToString live in NetworkAddress.cpp: they are
	# the only part of the type that still compiles Boost.Asio, and keeping them
	# out of the header is what stops asio reaching most of src/. Every target
	# whose include closure touches NetworkAddress.h therefore has to link this
	# TU -- the type is no longer header-only.
	${CMAKE_SOURCE_DIR}/src/NetworkAddress.cpp
)

add_test (NAME OtherFunctionsTest
	COMMAND OtherFunctionsTest
)

target_include_directories (OtherFunctionsTest
	PRIVATE ${CMAKE_BINARY_DIR}
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
	# NetworkAddress.cpp, linked above, is the one TU that still compiles
	# Boost.Asio for its address parsing and formatting.
	PRIVATE ${Boost_INCLUDE_DIR}
)

target_link_libraries (OtherFunctionsTest
	muleunit
	mulecommon
	CRYPTOPP::CRYPTOPP
	${Boost_LIBRARIES}
)


# libwebcommon — JWT / JSON writer / route patterns. `webcommon` PUBLIC-links
# wxWidgets::BASE and CRYPTOPP::CRYPTOPP and exposes its own headers through
# INTERFACE_INCLUDE_DIRECTORIES, so each test target only needs to depend on
# `muleunit` and `webcommon`.

add_executable (CredentialsTest
	CredentialsTest.cpp
	# muleunit's MuleDebug.cpp needs CFormat for its backtrace path, which
	# is compiled in on glibc; without these the link fails on Linux while
	# passing on macOS.
	${CMAKE_SOURCE_DIR}/src/libs/common/Format.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/strerror_r.c
)

add_test (NAME CredentialsTest COMMAND CredentialsTest)

target_link_libraries (CredentialsTest
	muleunit
	webcommon
)

add_executable (JwtTest
	JwtTest.cpp
)
add_test (NAME JwtTest COMMAND JwtTest)
target_link_libraries (JwtTest
	muleunit
	webcommon
	mulecommon
)

add_executable (ECCryptTest
	ECCryptTest.cpp
	${CMAKE_SOURCE_DIR}/src/libs/ec/cpp/ECCrypt.cpp
)
add_test (NAME ECCryptTest COMMAND ECCryptTest)
target_include_directories (ECCryptTest
	PRIVATE ${CMAKE_BINARY_DIR}
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/libs/ec/cpp
)
target_link_libraries (ECCryptTest
	muleunit
	mulecommon
	CRYPTOPP::CRYPTOPP
)

add_executable (SharedFilesReloadLatchTest
	SharedFilesReloadLatchTest.cpp
)
add_test (NAME SharedFilesReloadLatchTest COMMAND SharedFilesReloadLatchTest)
target_include_directories (SharedFilesReloadLatchTest
	PRIVATE ${CMAKE_BINARY_DIR}
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
)
target_link_libraries (SharedFilesReloadLatchTest
	muleunit
	mulecommon
)

add_executable (ChatSessionStoreTest
	ChatSessionStoreTest.cpp
	${CMAKE_SOURCE_DIR}/src/ChatSessionStore.cpp
	# CNetworkAddress::FromString/ToString live in NetworkAddress.cpp: they are
	# the only part of the type that still compiles Boost.Asio, and keeping them
	# out of the header is what stops asio reaching most of src/. Every target
	# whose include closure touches NetworkAddress.h therefore has to link this
	# TU -- the type is no longer header-only.
	${CMAKE_SOURCE_DIR}/src/NetworkAddress.cpp
)
add_test (NAME ChatSessionStoreTest COMMAND ChatSessionStoreTest)
target_include_directories (ChatSessionStoreTest
	PRIVATE ${CMAKE_BINARY_DIR}
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
	# NetworkAddress.cpp, linked above, is the one TU that still compiles
	# Boost.Asio for its address parsing and formatting.
	PRIVATE ${Boost_INCLUDE_DIR}
)
target_link_libraries (ChatSessionStoreTest
	muleunit
	mulecommon
	${Boost_LIBRARIES}
)

add_executable (MediaProbeParseTest
	MediaProbeParseTest.cpp
	${CMAKE_SOURCE_DIR}/src/MediaProbe.cpp
)
add_test (NAME MediaProbeParseTest COMMAND MediaProbeParseTest)
target_include_directories (MediaProbeParseTest
	PRIVATE ${CMAKE_BINARY_DIR}
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
)
target_link_libraries (MediaProbeParseTest
	muleunit
	mulecommon
)

add_executable (JsonWriterTest
	JsonWriterTest.cpp
)
add_test (NAME JsonWriterTest COMMAND JsonWriterTest)
target_link_libraries (JsonWriterTest
	muleunit
	webcommon
	mulecommon
)

add_executable (PathPatternsTest
	PathPatternsTest.cpp
)
add_test (NAME PathPatternsTest COMMAND PathPatternsTest)
target_link_libraries (PathPatternsTest
	muleunit
	webcommon
	mulecommon
)

add_executable (EtagTest
	EtagTest.cpp
)
add_test (NAME EtagTest COMMAND EtagTest)
target_link_libraries (EtagTest
	muleunit
	webcommon
	mulecommon
)

add_executable (StaticFsTest
	StaticFsTest.cpp
	${CMAKE_SOURCE_DIR}/src/webapi/StaticFs.cpp
)
target_include_directories (StaticFsTest
	PRIVATE ${CMAKE_SOURCE_DIR}/src/webapi
)
add_test (NAME StaticFsTest COMMAND StaticFsTest)
target_link_libraries (StaticFsTest
	muleunit
	mulecommon
)

# amuleapi shared-file content endpoint: path containment against the
# share-root list, Range parsing, and the Content-Disposition builder.
# SharedContent.cpp is plain std/POSIX (no wx, Beast or EC), same as
# StaticFs.cpp, so it links standalone here.
add_executable (SharedContentTest
	SharedContentTest.cpp
	${CMAKE_SOURCE_DIR}/src/webapi/SharedContent.cpp
)
target_include_directories (SharedContentTest
	PRIVATE ${CMAKE_SOURCE_DIR}/src/webapi
)
add_test (NAME SharedContentTest COMMAND SharedContentTest)
target_link_libraries (SharedContentTest
	muleunit
	mulecommon
)

add_executable (EventBusTest
	EventBusTest.cpp
	${CMAKE_SOURCE_DIR}/src/webapi/EventBus.cpp
)
target_include_directories (EventBusTest
	PRIVATE ${CMAKE_SOURCE_DIR}/src/webapi
)
add_test (NAME EventBusTest COMMAND EventBusTest)
target_link_libraries (EventBusTest
	muleunit
	mulecommon
)

# CEventBus's std::atomic<uint64_t> event counter needs libatomic on
# 32-bit targets without a hardware 8-byte CAS (PPC32, ARMv5/v6,
# MIPS32); same reason amuleapi links it. Empty on 64-bit.
if (LIBATOMIC)
	target_link_libraries (EventBusTest ${LIBATOMIC})
endif()

# amuleapi log-file tee: exercises CRotatingLog's append + two-file size cap.
# LogTee.cpp is plain POSIX/std (no wx), so only muleunit + mulecommon are
# needed for the harness.
add_executable (LogTeeTest
	LogTeeTest.cpp
	${CMAKE_SOURCE_DIR}/src/webapi/LogTee.cpp
)
target_include_directories (LogTeeTest
	PRIVATE ${CMAKE_SOURCE_DIR}/src/webapi
)
add_test (NAME LogTeeTest COMMAND LogTeeTest)
target_link_libraries (LogTeeTest
	muleunit
	mulecommon
)

# Tests for EmitDiffsAndUpdate's log_appended path and cold-start
# gating. Pulls EventBus + State along with EventDiff itself — no EC,
# and the only wx dependency is the shared search-result writer below.
add_executable (EventDiffTest
	EventDiffTest.cpp
	${CMAKE_SOURCE_DIR}/src/webapi/EventBus.cpp
	${CMAKE_SOURCE_DIR}/src/webapi/EventDiff.cpp
	# search_result_added is documented as carrying exactly a results-list
	# entry, so EventDiff emits it through the same writer the REST handler
	# uses instead of a second hand-rolled copy. That writer speaks
	# CJsonWriter, which is what brings webcommon (and wx base) in here.
	${CMAKE_SOURCE_DIR}/src/webapi/SearchJson.cpp
	${CMAKE_SOURCE_DIR}/src/webapi/State.cpp
)
target_include_directories (EventDiffTest
	PRIVATE ${CMAKE_SOURCE_DIR}/src/webapi
	# ServerFlagNames.h reads the SRV_*FLG_* masks straight from the eD2k
	# protocol headers rather than restating them.
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
)
add_test (NAME EventDiffTest COMMAND EventDiffTest)
target_link_libraries (EventDiffTest
	muleunit
	mulecommon
	webcommon
	wxWidgets::BASE
)

# Pulls EventBus.cpp, so it needs libatomic on 32-bit targets too.
if (LIBATOMIC)
	target_link_libraries (EventDiffTest ${LIBATOMIC})
endif()

# amuleapi-specific: tests CAmuleApiConfig's file-IO + mode-bit
# enforcement. AmuleApiConfig.cpp is statically linked into the test
# binary (rather than a webapi-side static lib) — it's a single TU and
# the amuleapi exe is the only other consumer, so an extra library
# target for one TU would just add noise.
add_executable (AmuleApiConfigTest
	AmuleApiConfigTest.cpp
	${CMAKE_SOURCE_DIR}/src/webapi/AmuleApiConfig.cpp
)
add_test (NAME AmuleApiConfigTest COMMAND AmuleApiConfigTest)
target_include_directories (AmuleApiConfigTest
	PRIVATE ${CMAKE_SOURCE_DIR}/src/webapi
)
target_link_libraries (AmuleApiConfigTest
	muleunit
	webcommon
	mulecommon
	wxWidgets::BASE
)

# amuleapi auth state — revocation set, rate limiter, header
# extraction, ISO-8601 formatter. Same vendoring pattern as the
# Config test: Auth.cpp is pulled in directly because amuleapi is
# the only other consumer.
add_executable (AuthTest
	AuthTest.cpp
	${CMAKE_SOURCE_DIR}/src/webapi/Auth.cpp
)
add_test (NAME AuthTest COMMAND AuthTest)
target_include_directories (AuthTest
	PRIVATE ${CMAKE_SOURCE_DIR}/src/webapi
)
target_link_libraries (AuthTest
	muleunit
	webcommon
	mulecommon
)

# EC password-exchange throttle: exercises the limiter at the values the
# listener ships with. The limiter lives in mulecommon, so nothing
# webapi-specific is needed here.
add_executable (RateLimiterTest
	RateLimiterTest.cpp
)
add_test (NAME RateLimiterTest COMMAND RateLimiterTest)
target_link_libraries (RateLimiterTest
	muleunit
	mulecommon
)

# amuleapi state cache — snapshot semantics + concurrent-reader
# correctness on the shared_timed_mutex.
add_executable (StateTest
	StateTest.cpp
	${CMAKE_SOURCE_DIR}/src/webapi/State.cpp
)
add_test (NAME StateTest COMMAND StateTest)
target_include_directories (StateTest
	PRIVATE ${CMAKE_SOURCE_DIR}/src/webapi
)
target_link_libraries (StateTest
	muleunit
	mulecommon
)

# amuleapi refresher — the pure EC-tag-to-State translation layer
# (Refresher.cpp) is linkable without the CamuleapiApp dependency
# tree because the orchestration body lives in RefresherTick.cpp
# (kept out of this target). Tests cover the EC_TAG_FILE_REMOVED
# delete marker, the alive-marker enqueue path, the unknown-ECID-
# no-op defence (#713-class race), and partial-update-active.
add_executable (RefresherTest
	RefresherTest.cpp
	# Refresher.cpp decodes EC_TAG_KAD_ID into a CUInt128; the class
	# lives outside libec, so the archive's ECUInt128.cpp cannot
	# resolve on its own. Mirrors amuleapi's own webapi/CMakeLists.txt.
	${CMAKE_SOURCE_DIR}/src/kademlia/utils/UInt128.cpp
	${CMAKE_SOURCE_DIR}/src/webapi/PrefsSchema.cpp
	${CMAKE_SOURCE_DIR}/src/webapi/Refresher.cpp
	${CMAKE_SOURCE_DIR}/src/webapi/State.cpp
	# OtherFunctions.cpp ships the `CastIto*` / `CastSecondsToHM`
	# formatters that `CEC_StatTree_Node_Tag::GetDisplayString` pulls
	# in via libec.a's `FormatValue`. Without this the ParseStatsTree
	# test can't link.
	${CMAKE_SOURCE_DIR}/src/OtherFunctions.cpp
	# RLE.cpp ships `PartFileEncoderData` + the stateful `RLE_Data`
	# decoder Refresher.cpp uses for `progress.parts`. Required even
	# for tests that don't directly invoke the decoder — the public
	# Apply{Update,Full} signatures take `std::map<ecid,
	# PartFileEncoderData>&` so the class is part of the link.
	${CMAKE_SOURCE_DIR}/src/RLE.cpp
	# LoggerConsole.cpp provides the no-op DoECLogLine + theLogger
	# symbols that libec.a's Debug build references unconditionally
	# (ECPacket / ECSocket / ECTag debug-print paths). Release builds
	# preprocess these calls to `do {} while(0)` via the ECLog.h
	# define, so the symbols are unused there; macOS Debug + Ubuntu
	# Debug builds link them in. Mirror amuleapi's own webapi/
	# CMakeLists.txt, which already pulls this TU in.
	${CMAKE_SOURCE_DIR}/src/LoggerConsole.cpp
	# CNetworkAddress::FromString/ToString live in NetworkAddress.cpp: they are
	# the only part of the type that still compiles Boost.Asio, and keeping them
	# out of the header is what stops asio reaching most of src/. Every target
	# whose include closure touches NetworkAddress.h therefore has to link this
	# TU -- the type is no longer header-only.
	${CMAKE_SOURCE_DIR}/src/NetworkAddress.cpp
)
add_test (NAME RefresherTest COMMAND RefresherTest)
target_include_directories (RefresherTest
	PRIVATE ${CMAKE_SOURCE_DIR}/src/webapi
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
	PRIVATE ${CMAKE_BINARY_DIR}
	# NetworkAddress.cpp, linked above, is the one TU that still compiles
	# Boost.Asio for its address parsing and formatting.
	PRIVATE ${Boost_INCLUDE_DIR}
)
target_link_libraries (RefresherTest
	muleunit
	ec
	mulecommon
	mulesocket
	webcommon
	wxWidgets::NET
	${Boost_LIBRARIES}
)

# CompleteSourcesNeedRecompute decides whether the complete-sources throttle
# must be bypassed because the upload list went empty. #1052 added that bypass
# but guarded it on the scalar alone, leaving Hi stale (#1065), so the
# predicate now lives in a header of its own: CKnownFile reaches theApp and
# cannot be linked into a test.
add_executable (JsonDepthScanTest
	JsonDepthScanTest.cpp
)

add_test (NAME JsonDepthScanTest
	COMMAND JsonDepthScanTest
)

target_include_directories (JsonDepthScanTest
	PRIVATE ${CMAKE_BINARY_DIR}
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
	PRIVATE ${CMAKE_SOURCE_DIR}/src/webapi
)

# mulecommon even though the header is inline-only: macOS links without it,
# GNU ld and mingw do not.
target_link_libraries (JsonDepthScanTest
	muleunit
	mulecommon
)

add_executable (CompleteSourcesThrottleTest
	CompleteSourcesThrottleTest.cpp
)

add_test (NAME CompleteSourcesThrottleTest
	COMMAND CompleteSourcesThrottleTest
)

target_include_directories (CompleteSourcesThrottleTest
	PRIVATE ${CMAKE_BINARY_DIR}
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
)

# mulecommon even though the header is inline-only: macOS links without it,
# GNU ld and mingw do not.
target_link_libraries (CompleteSourcesThrottleTest
	muleunit
	mulecommon
)

# The browse ("View Files") state machine. Five separate defects have been the
# same machine going wrong in a place only a peer of the right kind could reach
# -- a flat browse that completes without ever being marked finished, a peer we
# decline to contact, a terminal browse still on the pending list (#1071 and
# its follow-ups). None were reachable from a test while the logic sat on
# CUpDownClient, so it lives in a pair of its own that touches no theApp.
add_executable (BrowseLifecycleTest
	BrowseLifecycleTest.cpp
	${CMAKE_SOURCE_DIR}/src/BrowseLifecycle.cpp
)

add_test (NAME BrowseLifecycleTest
	COMMAND BrowseLifecycleTest
)

target_include_directories (BrowseLifecycleTest
	PRIVATE ${CMAKE_BINARY_DIR}
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
)

target_link_libraries (BrowseLifecycleTest
	muleunit
	mulecommon
)

# The rules about browses -- one per peer, a terminal record outliving its
# client, a disconnect after success not being a failure. They used to live on
# CBrowseManager next to the notify and the log line, which put them out of a
# test's reach; the two defects found after the lifecycle was extracted were
# both here rather than in the state machine. The store identifies peers by an
# opaque key and touches no theApp, so all of it is drivable.
add_executable (BrowseStoreTest
	BrowseStoreTest.cpp
	${CMAKE_SOURCE_DIR}/src/BrowseStore.cpp
	${CMAKE_SOURCE_DIR}/src/BrowseLifecycle.cpp
)

add_test (NAME BrowseStoreTest
	COMMAND BrowseStoreTest
)

target_include_directories (BrowseStoreTest
	PRIVATE ${CMAKE_BINARY_DIR}
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
)

target_link_libraries (BrowseStoreTest
	muleunit
	mulecommon
)

# CListColumnStore maps a column id to its persistence key and default width.
# The key is the on-disk config format, so the id a caller registers has to be
# the id it looks the column up by -- a registry that renumbered stored ids
# would hand a saved width back to the wrong column, with nothing to see. Needs
# no GUI: the registry half of the class is plain wxString bookkeeping.
add_executable (ListColumnStoreTest
	ListColumnStoreTest.cpp
	${CMAKE_SOURCE_DIR}/src/ListColumnStore.cpp
)

add_test (NAME ListColumnStoreTest
	COMMAND ListColumnStoreTest
)

target_include_directories (ListColumnStoreTest
	PRIVATE ${CMAKE_BINARY_DIR}
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
)

target_link_libraries (ListColumnStoreTest
	muleunit
	mulecommon
)

# eMuleAI vendor capability bits (CT_MOD_MISCOPTIONS) and the "ip6"/"bi6" hex
# address encoding. Both are wire format shared with another implementation and
# both fail silently when wrong -- a misplaced bit makes aMule advertise a
# transport it does not have. CUpDownClient reaches theApp, so the model lives
# in a header of its own and is tested there.
add_executable (PeerCapabilitiesTest
	PeerCapabilitiesTest.cpp
	# The unknown-vendor-tag test reads a tag stream through the same classes
	# the handshake does, because the property it pins -- an unknown tag
	# consumes its own bytes -- is a wire property and not a client one. Same
	# TU set as CTagTest.
	${CMAKE_SOURCE_DIR}/src/SafeFile.cpp
	${CMAKE_SOURCE_DIR}/src/MemFile.cpp
	${CMAKE_SOURCE_DIR}/src/Tag.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/Format.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/strerror_r.c
	# CNetworkAddress::FromString/ToString live in NetworkAddress.cpp: they are
	# the only part of the type that still compiles Boost.Asio, and keeping them
	# out of the header is what stops asio reaching most of src/. Every target
	# whose include closure touches NetworkAddress.h therefore has to link this
	# TU -- the type is no longer header-only.
	${CMAKE_SOURCE_DIR}/src/NetworkAddress.cpp
)

add_test (NAME PeerCapabilitiesTest
	COMMAND PeerCapabilitiesTest
)

target_include_directories (PeerCapabilitiesTest
	PRIVATE ${CMAKE_BINARY_DIR}
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
	# NetworkAddress.cpp, linked above, is the one TU that still compiles
	# Boost.Asio for its address parsing and formatting.
	PRIVATE ${Boost_INCLUDE_DIR}
)

target_link_libraries (PeerCapabilitiesTest
	muleunit
	${Boost_LIBRARIES}
)

# OP_UDPRESERVEDPROT2 frame demultiplexing: the type byte, the payload window
# handed to each handler, the unknown-type drop, and the log throttle that
# keeps an unknown-frame flood from becoming a log flood. Same reason for the
# separate header: CClientUDPSocket needs theApp.
add_executable (ReservedProtocolFramesTest
	ReservedProtocolFramesTest.cpp
)

add_test (NAME ReservedProtocolFramesTest
	COMMAND ReservedProtocolFramesTest
)

target_include_directories (ReservedProtocolFramesTest
	PRIVATE ${CMAKE_BINARY_DIR}
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
)

target_link_libraries (ReservedProtocolFramesTest
	muleunit
	mulecommon
)

# The QUIC NAT-T transport, in two suites and no ngtcp2.
#
# Same reasoning as the uTP suites below, and one step stronger: QUIC's
# dependency is not packageable on every platform aMule ships on, so
# -DENABLE_QUIC=NO is not merely the default but the permanent configuration on
# macOS. Everything worth asserting therefore has to be assertable without
# ngtcp2 present at all -- the wire identity and the peer proof are header-only,
# and the context drives a fake IQuicLibrary.
#
# QuicNattProtocolTest links only muleunit and mulecommon: QuicNattProtocol.h
# reaches nothing but protocol/Protocols.h, which is #defines.
add_executable (QuicNattProtocolTest
	QuicNattProtocolTest.cpp
)

add_test (NAME QuicNattProtocolTest
	COMMAND QuicNattProtocolTest
)

target_include_directories (QuicNattProtocolTest
	PRIVATE ${CMAKE_BINARY_DIR}
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
)

target_link_libraries (QuicNattProtocolTest
	muleunit
	# muleunit's MuleDebug.cpp calls CFormat, so every test binary needs
	# mulecommon even when the code under test does not.
	mulecommon
)

# The identity value the proof's second field carries, and the derivation of
# this client's own. Two link closures in one target: the value type and the
# direction constant are header-only, while DeriveLocalQuicProofValue() needs
# cryptopp -- which is why the .cpp and CRYPTOPP::CRYPTOPP appear here and no wx
# does. Nothing in this suite reaches theApp, ngtcp2 or GnuTLS, so every branch
# is exercised in the default -DENABLE_QUIC=NO build.
add_executable (QuicProofValueTest
	QuicProofValueTest.cpp
	${CMAKE_SOURCE_DIR}/src/QuicProofValue.cpp
)

add_test (NAME QuicProofValueTest
	COMMAND QuicProofValueTest
)

target_include_directories (QuicProofValueTest
	PRIVATE ${CMAKE_BINARY_DIR}
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
)

target_link_libraries (QuicProofValueTest
	muleunit
	# muleunit's MuleDebug.cpp calls CFormat, so every test binary needs
	# mulecommon even when the code under test does not.
	mulecommon
	CRYPTOPP::CRYPTOPP
)

add_executable (QuicContextTest
	QuicContextTest.cpp
	# CNetworkAddress::FromString/ToString live in NetworkAddress.cpp: they are
	# the only part of the type that still compiles Boost.Asio, and keeping them
	# out of the header is what stops asio reaching most of src/. Every target
	# that touches an address therefore has to link this TU -- the type is no
	# longer header-only.
	${CMAKE_SOURCE_DIR}/src/NetworkAddress.cpp
)

add_test (NAME QuicContextTest
	COMMAND QuicContextTest
)

target_include_directories (QuicContextTest
	PRIVATE ${CMAKE_BINARY_DIR}
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
	# CNetworkAddress is a boost::asio::ip::address.
	PRIVATE ${Boost_INCLUDE_DIR}
)

target_link_libraries (QuicContextTest
	muleunit
	mulecommon
	${Boost_LIBRARIES}
)

# RangeFileBody is the Boost.Beast Body amuleapi serves shared content with: a
# bounded [first, last] window read through a fixed 64 KiB buffer. Header-only
# and free of wx and of the rest of the webapi tree, so the test compiles on
# its own -- it only needs the Boost headers amuleapi already builds against.
add_executable (RangeFileBodyTest
	RangeFileBodyTest.cpp
)

add_test (NAME RangeFileBodyTest
	COMMAND RangeFileBodyTest
)

target_include_directories (RangeFileBodyTest
	PRIVATE ${CMAKE_SOURCE_DIR}/src/webapi
	PRIVATE ${Boost_INCLUDE_DIR}
)

target_link_libraries (RangeFileBodyTest
	muleunit
	mulecommon
	${Boost_LIBRARIES}
)

# The QUIC byte-stream transport, and no ngtcp2. The library sits behind
# IQuicStreamWriter and the tests drive a fake, which is what makes the two
# behaviours with no visible failure mode assertable at all -- the write that
# must not enter ngtcp2 from the throttler thread, and the queue bound that a
# stalled peer would otherwise turn into unbounded memory.
add_executable (QuicSocketTransportTest
	QuicSocketTransportTest.cpp
	# CNetworkAddress::FromString/ToString live in NetworkAddress.cpp: they are
	# the only part of the type that still compiles Boost.Asio, and keeping them
	# out of the header is what stops asio reaching most of src/.
	${CMAKE_SOURCE_DIR}/src/NetworkAddress.cpp
)

add_test (NAME QuicSocketTransportTest
	COMMAND QuicSocketTransportTest
)

target_include_directories (QuicSocketTransportTest
	PRIVATE ${CMAKE_BINARY_DIR}
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
	# CNetworkAddress is a boost::asio::ip::address.
	PRIVATE ${Boost_INCLUDE_DIR}
)

target_link_libraries (QuicSocketTransportTest
	muleunit
	mulecommon
	${Boost_LIBRARIES}
)

# The uTP transport, in five suites and no libutp.
#
# Every one of these links nothing but muleunit, because the transport shim is
# header-only and free of theApp, of wxWidgets and of libutp itself: the library
# sits behind IUtpLibrary (UtpContext.h) and the tests drive a fake. That is
# what makes the two behaviours with no visible failure mode assertable at all
# -- the tick that must keep firing with no inbound traffic, and the write
# buffer that must grow under sustained blocking and shrink on a duplex
# transfer. Neither is observable through a real libutp without a peer on the
# network, and a build with -DENABLE_UTP=NO has no libutp to observe.
add_executable (UtpDatagramRoutingTest
	UtpDatagramRoutingTest.cpp
)

add_test (NAME UtpDatagramRoutingTest
	COMMAND UtpDatagramRoutingTest
)

target_include_directories (UtpDatagramRoutingTest
	PRIVATE ${CMAKE_BINARY_DIR}
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
)

target_link_libraries (UtpDatagramRoutingTest
	muleunit
	# muleunit's MuleDebug.cpp calls CFormat, so every test binary needs
	# mulecommon even when the code under test does not.
	mulecommon
)

add_executable (UtpContextTest
	UtpContextTest.cpp
	# CNetworkAddress::FromString/ToString live in NetworkAddress.cpp: they are
	# the only part of the type that still compiles Boost.Asio, and keeping them
	# out of the header is what stops asio reaching most of src/. Every target
	# that touches an address therefore has to link this TU -- the type is no
	# longer header-only.
	${CMAKE_SOURCE_DIR}/src/NetworkAddress.cpp
)

add_test (NAME UtpContextTest
	COMMAND UtpContextTest
)

target_include_directories (UtpContextTest
	PRIVATE ${CMAKE_BINARY_DIR}
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
	# CNetworkAddress is a boost::asio::ip::address, so the endpoint the
	# context and the stream carry brings boost with it.
	PRIVATE ${Boost_INCLUDE_DIR}
)

target_link_libraries (UtpContextTest
	muleunit
	mulecommon
	${Boost_LIBRARIES}
)

add_executable (UtpWriteBufferPolicyTest
	UtpWriteBufferPolicyTest.cpp
)

add_test (NAME UtpWriteBufferPolicyTest
	COMMAND UtpWriteBufferPolicyTest
)

target_include_directories (UtpWriteBufferPolicyTest
	PRIVATE ${CMAKE_BINARY_DIR}
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
)

target_link_libraries (UtpWriteBufferPolicyTest
	muleunit
	# muleunit's MuleDebug.cpp calls CFormat, so every test binary needs
	# mulecommon even when the code under test does not.
	mulecommon
)

add_executable (UtpStreamTest
	UtpStreamTest.cpp
	# CNetworkAddress::FromString/ToString live in NetworkAddress.cpp: they are
	# the only part of the type that still compiles Boost.Asio, and keeping them
	# out of the header is what stops asio reaching most of src/. Every target
	# whose include closure touches NetworkAddress.h therefore has to link this
	# TU -- the type is no longer header-only.
	${CMAKE_SOURCE_DIR}/src/NetworkAddress.cpp
)

add_test (NAME UtpStreamTest
	COMMAND UtpStreamTest
)

target_include_directories (UtpStreamTest
	PRIVATE ${CMAKE_BINARY_DIR}
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
	# CNetworkAddress is a boost::asio::ip::address, so the endpoint the
	# context and the stream carry brings boost with it.
	PRIVATE ${Boost_INCLUDE_DIR}
)

target_link_libraries (UtpStreamTest
	muleunit
	mulecommon
	${Boost_LIBRARIES}
)

add_executable (UtpTransportFailureTest
	UtpTransportFailureTest.cpp
)

add_test (NAME UtpTransportFailureTest
	COMMAND UtpTransportFailureTest
)

target_include_directories (UtpTransportFailureTest
	PRIVATE ${CMAKE_BINARY_DIR}
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
)

target_link_libraries (UtpTransportFailureTest
	muleunit
	# muleunit's MuleDebug.cpp calls CFormat, so every test binary needs
	# mulecommon even when the code under test does not.
	mulecommon
)

# The three suites the live transport added. Same shape as the five above and
# for the same reason: the substitution, the dial decision and the accept path
# are all header-only and libutp-free, so the fake IUtpLibrary is what makes
# both answers to each question reachable in one build. Only one of them exists
# in any given real build, and the wrong one produces no symptom.
add_executable (UtpDialPolicyTest
	UtpDialPolicyTest.cpp
	# CNetworkAddress::FromString/ToString live in NetworkAddress.cpp: they are
	# the only part of the type that still compiles Boost.Asio, and keeping them
	# out of the header is what stops asio reaching most of src/. Every target
	# that touches an address therefore has to link this TU -- the type is no
	# longer header-only.
	${CMAKE_SOURCE_DIR}/src/NetworkAddress.cpp
)

add_test (NAME UtpDialPolicyTest
	COMMAND UtpDialPolicyTest
)

target_include_directories (UtpDialPolicyTest
	PRIVATE ${CMAKE_BINARY_DIR}
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
	# CNetworkAddress is a boost::asio::ip::address.
	PRIVATE ${Boost_INCLUDE_DIR}
)

target_link_libraries (UtpDialPolicyTest
	muleunit
	mulecommon
	${Boost_LIBRARIES}
)

# The obfuscation gate for outbound NAT traversal frames. Header-only and
# wx-free for the same reason as the dial policy above, and linked against
# NetworkAddress.cpp because the routability predicate the gate delegates to
# lives on CNetworkAddress -- whose FromString() is still the one part of the
# type that compiles Boost.Asio.
add_executable (UtpEncryptionPolicyTest
	UtpEncryptionPolicyTest.cpp
	${CMAKE_SOURCE_DIR}/src/NetworkAddress.cpp
)

add_test (NAME UtpEncryptionPolicyTest
	COMMAND UtpEncryptionPolicyTest
)

target_include_directories (UtpEncryptionPolicyTest
	PRIVATE ${CMAKE_BINARY_DIR}
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
	# CNetworkAddress is a boost::asio::ip::address.
	PRIVATE ${Boost_INCLUDE_DIR}
)

target_link_libraries (UtpEncryptionPolicyTest
	muleunit
	mulecommon
	${Boost_LIBRARIES}
)

add_executable (UtpSocketTransportTest
	UtpSocketTransportTest.cpp
	# CNetworkAddress::FromString/ToString live in NetworkAddress.cpp: they are
	# the only part of the type that still compiles Boost.Asio, and keeping them
	# out of the header is what stops asio reaching most of src/. Every target
	# that touches an address therefore has to link this TU -- the type is no
	# longer header-only.
	${CMAKE_SOURCE_DIR}/src/NetworkAddress.cpp
)

add_test (NAME UtpSocketTransportTest
	COMMAND UtpSocketTransportTest
)

target_include_directories (UtpSocketTransportTest
	PRIVATE ${CMAKE_BINARY_DIR}
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
	PRIVATE ${Boost_INCLUDE_DIR}
)

target_link_libraries (UtpSocketTransportTest
	muleunit
	mulecommon
	${Boost_LIBRARIES}
)

add_executable (UtpInboundAcceptTest
	UtpInboundAcceptTest.cpp
	# CNetworkAddress::FromString/ToString live in NetworkAddress.cpp: they are
	# the only part of the type that still compiles Boost.Asio, and keeping them
	# out of the header is what stops asio reaching most of src/. Every target
	# that touches an address therefore has to link this TU -- the type is no
	# longer header-only.
	${CMAKE_SOURCE_DIR}/src/NetworkAddress.cpp
)

add_test (NAME UtpInboundAcceptTest
	COMMAND UtpInboundAcceptTest
)

target_include_directories (UtpInboundAcceptTest
	PRIVATE ${CMAKE_BINARY_DIR}
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
	PRIVATE ${Boost_INCLUDE_DIR}
)

target_link_libraries (UtpInboundAcceptTest
	muleunit
	mulecommon
	${Boost_LIBRARIES}
)

# EC_TAG_CLIENT_MOD_CAPABILITIES: the headless view of a peer's negotiated
# vendor capabilities. The Client Details dialog that renders the same data
# lives in amule/amulegui and needs an X server, so this tag is what makes that
# display observable in CI -- and its encoding is pinned here rather than in a
# GUI nobody can open. Same TU set and the same LoggerConsole.cpp reason as
# ECIdDiffTest.
add_executable (ECClientCapabilitiesTest
	ECClientCapabilitiesTest.cpp
	${CMAKE_SOURCE_DIR}/src/LoggerConsole.cpp
)

add_test (NAME ECClientCapabilitiesTest
	COMMAND ECClientCapabilitiesTest
)

target_include_directories (ECClientCapabilitiesTest
	PRIVATE ${CMAKE_BINARY_DIR}
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
	PRIVATE ${CMAKE_SOURCE_DIR}/src/libs
	PRIVATE ${CMAKE_BINARY_DIR}/src/libs
	PRIVATE ${CMAKE_BINARY_DIR}/src/libs/ec/cpp
)

target_link_libraries (ECClientCapabilitiesTest
	muleunit
	ec
	mulecommon
)

# The internal address type introduced by amule-address-widening. Byte order in
# the signature, absence distinct from 0.0.0.0, explicit failure instead of
# truncation, and a total order -- all of it value-type behaviour over
# boost::asio::ip::address, so no app and no daemon.
add_executable (NetworkAddressTest
	NetworkAddressTest.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/Format.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/strerror_r.c
	# CNetworkAddress::FromString/ToString live in NetworkAddress.cpp: they are
	# the only part of the type that still compiles Boost.Asio, and keeping them
	# out of the header is what stops asio reaching most of src/. Every target
	# that touches an address therefore has to link this TU -- the type is no
	# longer header-only.
	${CMAKE_SOURCE_DIR}/src/NetworkAddress.cpp
)

add_test (NAME NetworkAddressTest
	COMMAND NetworkAddressTest
)

target_include_directories (NetworkAddressTest
	PRIVATE ${CMAKE_BINARY_DIR}
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
	PRIVATE ${Boost_INCLUDE_DIR}
)

target_link_libraries (NetworkAddressTest
	muleunit
	${Boost_LIBRARIES}
)

# Characterisation of the address behaviour amule-address-widening must not
# change: IP filter range matching and its byte order, client-list address
# keying, and the bytes an address occupies on the wire. These hold current
# behaviour, not intended behaviour -- editing one to make a refactor pass means
# the refactor changed behaviour.
add_executable (AddressCharacterisationTest
	AddressCharacterisationTest.cpp
	${CMAKE_SOURCE_DIR}/src/SafeFile.cpp
	${CMAKE_SOURCE_DIR}/src/MemFile.cpp
	${CMAKE_SOURCE_DIR}/src/Tag.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/Format.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/strerror_r.c
	# CNetworkAddress::FromString/ToString live in NetworkAddress.cpp: they are
	# the only part of the type that still compiles Boost.Asio, and keeping them
	# out of the header is what stops asio reaching most of src/. Every target
	# that touches an address therefore has to link this TU -- the type is no
	# longer header-only.
	${CMAKE_SOURCE_DIR}/src/NetworkAddress.cpp
)

add_test (NAME AddressCharacterisationTest
	COMMAND AddressCharacterisationTest
)

target_include_directories (AddressCharacterisationTest
	PRIVATE ${CMAKE_BINARY_DIR}
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
	PRIVATE ${Boost_INCLUDE_DIR}
)

target_link_libraries (AddressCharacterisationTest
	muleunit
	${Boost_LIBRARIES}
)

# The listener plan of amule-dual-stack-reachability: which sockets are tried,
# in which order, the fallback when a platform refuses a dual-stack socket, and
# the once-per-family-per-start bind-failure latch. Decision logic over the
# configured family set, so the three cases the spec names are reachable without
# a host that has (or lacks) each network stack.
add_executable (DualStackListenerTest
	DualStackListenerTest.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/Format.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/strerror_r.c
	# CNetworkAddress::FromString/ToString live in NetworkAddress.cpp: they are
	# the only part of the type that still compiles Boost.Asio, and keeping them
	# out of the header is what stops asio reaching most of src/. Every target
	# whose include closure touches NetworkAddress.h therefore has to link this
	# TU -- the type is no longer header-only.
	${CMAKE_SOURCE_DIR}/src/NetworkAddress.cpp
)

add_test (NAME DualStackListenerTest
	COMMAND DualStackListenerTest
)

target_include_directories (DualStackListenerTest
	PRIVATE ${CMAKE_BINARY_DIR}
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
	PRIVATE ${Boost_INCLUDE_DIR}
)

target_link_libraries (DualStackListenerTest
	muleunit
	${Boost_LIBRARIES}
)

# Outbound family selection and, more importantly, the dead-peer accounting: a
# peer advertising two families must not be written off on the first connect
# error. No app needed -- the accounting is a value type over CNetworkAddress.
add_executable (OutboundFamilyFallbackTest
	OutboundFamilyFallbackTest.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/Format.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/strerror_r.c
	# CNetworkAddress::FromString/ToString live in NetworkAddress.cpp: they are
	# the only part of the type that still compiles Boost.Asio, and keeping them
	# out of the header is what stops asio reaching most of src/. Every target
	# that touches an address therefore has to link this TU -- the type is no
	# longer header-only.
	${CMAKE_SOURCE_DIR}/src/NetworkAddress.cpp
)

add_test (NAME OutboundFamilyFallbackTest
	COMMAND OutboundFamilyFallbackTest
)

target_include_directories (OutboundFamilyFallbackTest
	PRIVATE ${CMAKE_BINARY_DIR}
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
	PRIVATE ${Boost_INCLUDE_DIR}
)

target_link_libraries (OutboundFamilyFallbackTest
	muleunit
	${Boost_LIBRARIES}
)

# The IP filter's IPv6 prefix table and the IPv4-mapped bypass it has to
# survive. Security relevant: with an IPv6 socket bound, a blocked IPv4 peer can
# reconnect as ::ffff:a.b.c.d, and this pins that it stays blocked and that the
# block still names the IPv4 rule. CIPFilter itself is a wxEvtHandler that reads
# thePrefs and writes theStats, hence the separate header under test.
add_executable (IPFilterIPv6Test
	IPFilterIPv6Test.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/Format.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/strerror_r.c
	# CNetworkAddress::FromString/ToString live in NetworkAddress.cpp: they are
	# the only part of the type that still compiles Boost.Asio, and keeping them
	# out of the header is what stops asio reaching most of src/. Every target
	# that touches an address therefore has to link this TU -- the type is no
	# longer header-only.
	${CMAKE_SOURCE_DIR}/src/NetworkAddress.cpp
)

add_test (NAME IPFilterIPv6Test
	COMMAND IPFilterIPv6Test
)

target_include_directories (IPFilterIPv6Test
	PRIVATE ${CMAKE_BINARY_DIR}
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
	PRIVATE ${Boost_INCLUDE_DIR}
)

target_link_libraries (IPFilterIPv6Test
	muleunit
	${Boost_LIBRARIES}
)

# What aMule may claim about its own IPv6 reachability, and when: a bound socket
# is not verification. Also covers the reachability display, which the local GUI
# and the remote GUI render from one function here -- with the EC word both
# sides pass it through pinned as literals.
add_executable (IPv6ReachabilityTest
	IPv6ReachabilityTest.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/Format.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/strerror_r.c
	# CNetworkAddress::FromString/ToString live in NetworkAddress.cpp: they are
	# the only part of the type that still compiles Boost.Asio, and keeping them
	# out of the header is what stops asio reaching most of src/. Every target
	# whose include closure touches NetworkAddress.h therefore has to link this
	# TU -- the type is no longer header-only.
	${CMAKE_SOURCE_DIR}/src/NetworkAddress.cpp
)

add_test (NAME IPv6ReachabilityTest
	COMMAND IPv6ReachabilityTest
)

target_include_directories (IPv6ReachabilityTest
	PRIVATE ${CMAKE_BINARY_DIR}
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
	PRIVATE ${Boost_INCLUDE_DIR}
)

target_link_libraries (IPv6ReachabilityTest
	muleunit
	${Boost_LIBRARIES}
)

# Peer identity: what makes two peers the same peer once a peer can be IPv6, how
# much of an IPv6 address a rate limit counts against, and how far an inbound
# datagram can be routed. All decision logic over CNetworkAddress, so it is
# testable without an app -- which is why it lives in a header of its own rather
# than inside CClientList.
add_executable (PeerIdentityTest
	PeerIdentityTest.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/Format.cpp
	${CMAKE_SOURCE_DIR}/src/libs/common/strerror_r.c
	# CNetworkAddress::FromString/ToString live in NetworkAddress.cpp: they are
	# the only part of the type that still compiles Boost.Asio, and keeping them
	# out of the header is what stops asio reaching most of src/. Every target
	# whose include closure touches NetworkAddress.h therefore has to link this
	# TU -- the type is no longer header-only.
	${CMAKE_SOURCE_DIR}/src/NetworkAddress.cpp
)

add_test (NAME PeerIdentityTest
	COMMAND PeerIdentityTest
)

target_include_directories (PeerIdentityTest
	PRIVATE ${CMAKE_BINARY_DIR}
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
	PRIVATE ${Boost_INCLUDE_DIR}
)

target_link_libraries (PeerIdentityTest
	muleunit
	${Boost_LIBRARIES}
)

# LowID-to-LowID rendezvous and hole punching, in four suites.
#
# The wire format comes first and is asserted as literal bytes, because the
# three opcodes and two option bits are eMuleAI's and an opcode off by one is a
# frame the peer drops -- which behind a NAT is indistinguishable from the NAT
# not opening.
#
# NatRendezvousRelayTest is the security suite and the reason the emission lives
# inside RelayRendezvousRequest() rather than in CClientUDPSocket: a rendezvous
# request asks this client to send packets toward an address on behalf of
# whoever asked, and "no packet is sent toward an unrelated address" is only
# assertable when the send is inside the unit under test. CClientUDPSocket needs
# theApp and cannot be linked into a test binary at all.
#
# Same shape and the same reasons as the uTP suites above: header-only, free of
# theApp and of wxWidgets, so both answers to each question are reachable in the
# one build a test binary is. Only one of them exists in any real build, and the
# wrong one produces no symptom.
add_executable (NatRendezvousProtocolTest
	NatRendezvousProtocolTest.cpp
	# CNetworkAddress::FromString/ToString live in NetworkAddress.cpp: they are
	# the only part of the type that still compiles Boost.Asio, and keeping them
	# out of the header is what stops asio reaching most of src/. Every target
	# that touches an address therefore has to link this TU -- the type is no
	# longer header-only.
	${CMAKE_SOURCE_DIR}/src/NetworkAddress.cpp
)

add_test (NAME NatRendezvousProtocolTest
	COMMAND NatRendezvousProtocolTest
)

target_include_directories (NatRendezvousProtocolTest
	PRIVATE ${CMAKE_BINARY_DIR}
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
	# CNetworkAddress is a boost::asio::ip::address.
	PRIVATE ${Boost_INCLUDE_DIR}
)

target_link_libraries (NatRendezvousProtocolTest
	muleunit
	# muleunit's MuleDebug.cpp calls CFormat, so every test binary needs
	# mulecommon even when the code under test does not.
	mulecommon
	${Boost_LIBRARIES}
)

add_executable (NatRendezvousRelayTest
	NatRendezvousRelayTest.cpp
	# CNetworkAddress::FromString/ToString live in NetworkAddress.cpp: they are
	# the only part of the type that still compiles Boost.Asio, and keeping them
	# out of the header is what stops asio reaching most of src/. Every target
	# that touches an address therefore has to link this TU -- the type is no
	# longer header-only.
	${CMAKE_SOURCE_DIR}/src/NetworkAddress.cpp
)

add_test (NAME NatRendezvousRelayTest
	COMMAND NatRendezvousRelayTest
)

target_include_directories (NatRendezvousRelayTest
	PRIVATE ${CMAKE_BINARY_DIR}
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
	PRIVATE ${Boost_INCLUDE_DIR}
)

target_link_libraries (NatRendezvousRelayTest
	muleunit
	mulecommon
	${Boost_LIBRARIES}
)

add_executable (NatHolePunchScheduleTest
	NatHolePunchScheduleTest.cpp
	# CNetworkAddress::FromString/ToString live in NetworkAddress.cpp: they are
	# the only part of the type that still compiles Boost.Asio, and keeping them
	# out of the header is what stops asio reaching most of src/. Every target
	# whose include closure touches NetworkAddress.h therefore has to link this
	# TU -- the type is no longer header-only.
	${CMAKE_SOURCE_DIR}/src/NetworkAddress.cpp
)

add_test (NAME NatHolePunchScheduleTest
	COMMAND NatHolePunchScheduleTest
)

target_include_directories (NatHolePunchScheduleTest
	PRIVATE ${CMAKE_BINARY_DIR}
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
	PRIVATE ${Boost_INCLUDE_DIR}
)

target_link_libraries (NatHolePunchScheduleTest
	muleunit
	mulecommon
	${Boost_LIBRARIES}
)

add_executable (NatTraversalPolicyTest
	NatTraversalPolicyTest.cpp
	# CNetworkAddress::FromString/ToString live in NetworkAddress.cpp: they are
	# the only part of the type that still compiles Boost.Asio, and keeping them
	# out of the header is what stops asio reaching most of src/. Every target
	# that touches an address therefore has to link this TU -- the type is no
	# longer header-only.
	${CMAKE_SOURCE_DIR}/src/NetworkAddress.cpp
)

add_test (NAME NatTraversalPolicyTest
	COMMAND NatTraversalPolicyTest
)

target_include_directories (NatTraversalPolicyTest
	PRIVATE ${CMAKE_BINARY_DIR}
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
	PRIVATE ${Boost_INCLUDE_DIR}
)

target_link_libraries (NatTraversalPolicyTest
	muleunit
	mulecommon
	${Boost_LIBRARIES}
)

# The set of in-flight exchanges, which is what the receive path and the core
# timer drive. Separate from NatHolePunchScheduleTest because the bounds that
# matter here are the ones that are right for one pair and wrong for the set:
# cancellation that must not leak across pairs, and a table an inbound packet
# can grow.
add_executable (NatRendezvousManagerTest
	NatRendezvousManagerTest.cpp
	# CNetworkAddress::FromString/ToString live in NetworkAddress.cpp: they are
	# the only part of the type that still compiles Boost.Asio, and keeping them
	# out of the header is what stops asio reaching most of src/. Every target
	# that touches an address therefore has to link this TU -- the type is no
	# longer header-only.
	${CMAKE_SOURCE_DIR}/src/NetworkAddress.cpp
)

add_test (NAME NatRendezvousManagerTest
	COMMAND NatRendezvousManagerTest
)

target_include_directories (NatRendezvousManagerTest
	PRIVATE ${CMAKE_BINARY_DIR}
	PRIVATE ${CMAKE_SOURCE_DIR}/src
	PRIVATE ${CMAKE_SOURCE_DIR}/src/include
	PRIVATE ${Boost_INCLUDE_DIR}
)

target_link_libraries (NatRendezvousManagerTest
	muleunit
	mulecommon
	${Boost_LIBRARIES}
)

# The two part-index predicates behind `next_requested_part_index` /
# `downloading_part_index` on the per-file client rows. Every branch that
# matters turns on a value a live peer will not produce on request -- the
# 0xffff sentinel, the boundary at part_count, a file with more than 65535
# parts, a source whose state flips to "downloading" -- so PartIndex.h is
# header-only and free of wx, Beast and EC, and the test needs nothing but
# the harness.
# The chunk-bar palette and the two legends the "?" beside the bar column
# headers opens. Header-only and wx-free on purpose (see PartBarLegend.h): the
# colours, the rows of each legend, which legend a column gets and where the "?"
# is clickable are all decided without a toolkit, so a headless run can check
# the half of the feature that can drift silently. Needs no app and no daemon.
add_executable (PartBarLegendTest
	PartBarLegendTest.cpp
)

add_test (NAME PartBarLegendTest
	COMMAND PartBarLegendTest
)

target_include_directories (PartBarLegendTest
	PRIVATE ${CMAKE_SOURCE_DIR}/src
)

# mulecommon even though the header is inline-only: macOS links without it,
# GNU ld and mingw do not (see JsonDepthScanTest).
target_link_libraries (PartBarLegendTest
	muleunit
	mulecommon
)

add_executable (PartIndexTest
	PartIndexTest.cpp
)

add_test (NAME PartIndexTest
	COMMAND PartIndexTest
)

target_include_directories (PartIndexTest
	PRIVATE ${CMAKE_SOURCE_DIR}/src/webapi
)

# mulecommon even though the header is inline-only: macOS links without it,
# GNU ld and mingw do not (see JsonDepthScanTest).
target_link_libraries (PartIndexTest
	muleunit
	mulecommon
)
