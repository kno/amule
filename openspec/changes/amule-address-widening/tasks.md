# Tasks: address widening

## 1. Type introduction

- [x] 1.1 Select `asio::ip::address` as the internal type; record the decision in design.md
- [x] 1.2 Add named, byte-order-explicit conversions to and from `uint32`
- [x] 1.3 Make the IPv6-to-32-bit conversion fail explicitly rather than truncate
- [x] 1.4 Add an absent-address representation distinct from the all-zero address
- [x] 1.5 Unit test: mapped-vs-native comparison, total ordering, failed narrowing

## 2. Characterisation tests first

- [x] 2.1 Capture current behaviour of IP filter matching
- [x] 2.2 Capture current behaviour of client-list address comparison
- [x] 2.3 Capture current address serialisation on the wire
- [x] 2.4 Hold these tests unchanged through the whole refactor

## 3. Socket backend

- [x] 3.1 Remove the `ip::tcp::v4()` pins at `LibSocketAsio.cpp:541`, `:785`, `:2183`
- [x] 3.2 Remove the `address_v4` pins at `:2160`, `:2237`
- [x] 3.3 Derive family from configuration or target address
- [x] 3.4 Unit test: family selection for v4 and v6 targets

## 4. Subsystem migration

- [x] 4.1 Migrate client list to the new type
- [x] 4.2 Migrate IP filter to the new type
- [x] 4.3 Leave the Kad interface on `uint32` behind a documented conversion boundary
- [x] 4.4 Audit every former zero-sentinel test and convert it to an explicit absence check

### 4.4 audit record

Converted, because both the test and the value it tests are inside the surface
this change migrates:

| Site | Was | Now |
| --- | --- | --- |
| `ClientList.cpp` `UpdateClientIP` | `if (newIP)` | `newIP.ToIPv4NetworkOrder()` succeeds |
| `ClientList.cpp` `RemoveIPFromList` | `if (!client->GetIP())` | `FromIPv4NetworkOrderOrAbsent(...).IsAbsent()` |
| `ClientList.cpp` `GetClientsByIP` | documented "zero yields nothing" | absent yields nothing, explicitly |
| `ClientList.cpp` banned-client trio | key `0` was bannable | absent bans nothing |
| `amuleIPV4Address.h` `Hostname(uint32)` | `if (!ip)` | `IsAbsent()` |
| `MuleUDPSocket.cpp` receive guard | `if (!ip)` | `IsAbsent() \|\| IsUnspecified()`, distinguished in the log |

Not converted, and why. Each of these tests a 32-bit field that this change
deliberately leaves at the `uint32` boundary, so converting the test alone would
move the conversion one line without removing the ambiguity — the ambiguity is
in the field, not in the test. They belong to whichever change widens the field.

| Site | Field still `uint32` because |
| --- | --- |
| `amule.cpp:2494` `m_dwPublicIP == 0` | local public IP, plumbed through Kad (4.3) |
| `amule.cpp:2507` `dwIP == 0` assertion | same field |
| `BaseClient.cpp:1525` `uClientIP == 0` | `CUpDownClient` still stores an ed2k `uint32` |
| `DownloadClient.cpp:71,97,115` | `CUpDownClient::GetIP()` comparisons |
| `Friend.cpp:102`, `ClientContextActions.cpp:66` | `CUpDownClient::GetIP()` |
| `ServerList.cpp:230`, `ServerWnd.cpp:210` | `CServer::GetIP()` |
| `ServerConnect.cpp:606`, `ServerUDPSocket.cpp:545` | ed2k server protocol fields |
| `KadDlg.cpp:184`, `ClientHistoryListCtrl.cpp:351` | GUI row structs fed from those fields |

## 5. Cleanup

- [x] 5.1 Retire conversion helpers with no remaining callers
- [x] 5.2 Confirm no new abstraction duplicates `asio::ip::address`

Retired in 5.1: `AddressFamilyPolicy::UdpProtocolForTarget` and
`CNetworkAddress::IsLoopback`. Neither gained a production caller — the UDP
socket already derives its protocol from the endpoint it binds
(`LibSocketAsio.cpp:1958`), and loopback tests in the tree go through
`IsLoopbackIP(uint32)`.

For 5.2: `CNetworkAddress` holds a `boost::asio::ip::address` and delegates
parsing, formatting and family classification to it. It adds exactly the two
things asio does not have — a byte-order-explicit 32-bit boundary and an absent
state distinct from the all-zero address — and reimplements nothing else.
eMuleAI's `CAddress` was not ported; there is no second abstraction.

## Building and testing this change

Do not assume a host toolchain. The supported route is the container:

```sh
packaging/linux/build.sh dev        # configures all three apps + tests, builds, runs ctest
```

Nothing is installed on the host. Compare any test failure against the
pre-existing failures in `openspec/BASELINE.md` before attributing it to this
change — see `openspec/changes/README.md`.
