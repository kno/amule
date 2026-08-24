# Tasks: dual-stack reachability

## 1. Listeners

- [x] 1.1 Create ed2k TCP listeners for both families
- [x] 1.2 Create ed2k UDP sockets for both families
- [x] 1.3 Attempt a dual-stack socket first; fall back to one socket per family
- [x] 1.4 Log a bind failure once per family per start, not per retry
- [x] 1.5 Unit test: single-family host, dual-stack rejection fallback

## 2. Outbound

- [x] 2.1 Select family from the target endpoint
- [x] 2.2 Implement cross-family fallback when a peer advertises both
- [x] 2.3 Do not mark a peer dead until every advertised family has failed
- [x] 2.4 Unit test: fallback ordering and dead-peer accounting

## 3. IP filter

- [x] 3.1 Extend rule storage and matching to IPv6 prefixes
- [x] 3.2 Normalise IPv4-mapped addresses to their IPv4 form before matching
- [x] 3.3 Unit test: mapped-address bypass attempt is blocked; IPv6 prefix rule matches

## 4. Advertisement

- [x] 4.1 Track verified inbound IPv6 connectivity separately from bound state
- [x] 4.2 Emit `SupportsIPv6`, `CT_MOD_IP_V6` and `"ip6"` only when verified
- [x] 4.3 Surface IPv4 and IPv6 reachability separately in the UI
- [~] 4.4 Interop check against an IPv6-reachable eMuleAI build — **NOT PERFORMED.**
      No eMuleAI build exists in this environment (it is Windows/MFC only and is
      not part of this tree), and the podman machine on this macOS host has no
      IPv6 transit to the internet, so neither side of the check could be
      stood up. No result is claimed. What was verified instead is on this side
      of the wire only: the tags, their byte values and their gating
      (`IPv6ReachabilityTest`, `PeerCapabilitiesTest`), and the listeners and
      filter rules at runtime in the dev container.

## 5. Peer identity

Closes the half of "Dual-family listening" that the listeners alone did not: an
inbound IPv6 peer was accepted and then dropped, because `CUpDownClient` and
`CClientList` could only identify a peer by a 32-bit address. This section
widens that identity. It also picks up the sites the archived
`amule-address-widening` task 4.4 audit deliberately left at the `uint32`
boundary *because the field was still `uint32`* -- widening the field is what
makes those checks convertible.

- [x] 5.1 Peer identity policy header: what is indexable, how an inbound
      datagram peer is routed, and the rate-limit scope per family
- [x] 5.2 Unit test: identity policy, IPv6 rate-limit scope, and the IPv4
      characterisation that must not change
- [x] 5.3 Widen `CUpDownClient`'s stored address, connect address and full
      address to `CNetworkAddress`; keep the 32-bit accessors as named
      narrowings
- [x] 5.4 Take the inbound TCP peer's address from the socket with its family
      intact, instead of the 32-bit form that is zero for an IPv6 peer
- [x] 5.5 Key `CClientList`'s IP index, banned list and tracked-client list on
      `CNetworkAddress`
- [x] 5.6 Unit test: index keying cannot merge an absent address with the
      all-zero one, and IPv4 grouping is unchanged
- [x] 5.7 Route inbound ed2k UDP by peer address: `CMuleUDPSocket` hands the
      handlers an address, Kad keeps its documented IPv4 boundary
- [x] 5.8 Unit test: UDP peer routing table, including the obfuscation
      boundary
- [x] 5.9 Convert the audit sites the widened fields make convertible
      (`BaseClient.cpp` `uClientIP == 0`, `DownloadClient.cpp` peer comparison,
      `Friend.cpp` last-used address)
- [x] 5.10 Widen the ed2k UDP send path so a reply to an IPv6 peer can leave:
      `CMuleUDPSocket`'s queue and `SendTo()` carry the address, and the
      obfuscation is skipped for a target with no 32-bit form
- [x] 5.11 Select the ed2k UDP socket by target family, so an outbound reask to
      an IPv6 peer does not leave through the IPV6_V6ONLY-incompatible IPv4
      socket
- [x] 5.12 Ban, unban and is-banned by address, and count the upload queue's
      per-peer slot cap in the peer's rate-limit scope -- a native IPv6 peer
      previously bypassed that cap entirely, its address narrowing to zero and
      the lookup finding nothing
- [x] 5.13 Keep a native IPv6 peer out of the ed2k formats that can only hold a
      32-bit address -- source exchange, the `.part.met.seeds` record, the
      relayed callback -- rather than publishing it as a zero, and its paired
      unit test. Needed *because* of 5.3: an IPv6 peer used to be excluded from
      those paths incidentally, by reading as LowID

### Per-IP and per-subnet limits under IPv6

Decided here rather than left implicit. Two families of limit exist in the tree
and they get different answers:

| Limit | Decision |
| --- | --- |
| `CRoutingBin::MAX_CONTACTS_IP` / `MAX_CONTACTS_SUBNET` | Unchanged. Kad is IPv4 behind a documented conversion boundary (`amule-address-widening` design), so there is no IPv6 contact to count. |
| `CClientList` callback-request throttle | Keyed on the *rate-limit scope*: the exact address for IPv4, the /64 prefix for IPv6. |
| `CUploadQueue`'s three-slots-per-peer cap | Same scope. This one was not merely IPv4-shaped -- it did not apply to a native IPv6 peer at all, because the peer's address narrowed to zero and the lookup found nobody. |

The /64 is the reason this needed deciding. An IPv4 per-address limit assumes an
address is roughly a host. Under IPv6 a single subscriber is routinely delegated
a /64 and can source each request from a fresh address, so a per-/128 limit
counts to one forever and throttles nothing. Aggregating at /64 makes the limit
mean what it meant under IPv4 -- one subscriber, one budget -- and stops short
of /48 or /56 aggregation, which would put unrelated subscribers of the same
provider in one bucket and let one of them lock out the others.


### What is now handled, and what is still not

An inbound native IPv6 ed2k UDP datagram is handled end to end: received,
ban-checked against an address-keyed ban list, routed by
`PeerIdentity::ClassifyUdpPeer()`, matched to a peer by address in the upload
queue and the download queue, and **answered on the IPv6 socket it arrived on**.
The reply path needed widening too -- `CMuleUDPSocket`'s queue held a 32-bit
target, so before this the reply was queued and then dropped by its own
`if (!IP)` guard, which would have made the receive side look like it worked.

Three boundaries remain, each named here rather than left to be discovered:

| Boundary | Why it stays |
| --- | --- |
| Kad over IPv6 | Kad's addresses are 32-bit on its own wire. A Kad datagram from an IPv6 peer is dropped with the boundary named in the log. Pinned by change 3's design; not this change's call to make. |
| ed2k UDP obfuscation to or from an IPv6 peer | The key is MD5 over a user hash, a **32-bit** address and a magic byte, on both sides. No IPv6 input exists in the protocol, so an obfuscated datagram between an IPv6 pair is undecryptable by any implementation. Unobfuscated ed2k UDP is unaffected and fully handled. |
| The address a client shows over EC | `EC_TAG_CLIENT_USER_IP` is a 32-bit tag, so amulegui and the web API show no address for a native IPv6 peer. Widening it means a new tag behind a capability gate -- the same rule this change set applies to every wire format. |

Sites from the archived `amule-address-widening` audit that stay at the 32-bit
boundary, with the reason updated now that the client's own field is wider:

| Site | Why it stays |
| --- | --- |
| `Friend.cpp:102` | `emfriends.met` persists a 32-bit address, and the read goes through `CClientRef`, which amulegui also links -- where the client's address is the 32-bit EC tag above. Two format changes, each needing its own gate. |
| `ClientContextActions.cpp:66` | Same `CClientRef` path: shared GUI code over both client classes. |
| `amule.cpp:2494`, `:2507` | Our own public IP, plumbed through Kad. |
| `ServerList.cpp`, `ServerWnd.cpp`, `ServerConnect.cpp`, `ServerUDPSocket.cpp` | `CServer` and the ed2k server protocol. No ed2k server in this tree is reachable over IPv6; `CServerUDPSocket` now drops a non-IPv4 datagram with that reason instead of narrowing it. |
| `KadDlg.cpp`, `ClientHistoryListCtrl.cpp` | GUI row structs fed from the fields above. |

## Building and testing this change

Do not assume a host toolchain. The supported route is the container:

```sh
packaging/linux/build.sh dev        # configures all three apps + tests, builds, runs ctest
```

Nothing is installed on the host. Compare any test failure against the
pre-existing failures in `openspec/BASELINE.md` before attributing it to this
change — see `openspec/changes/README.md`.
