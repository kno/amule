# Delta for network-ipv6

## ADDED Requirements

### Requirement: Dual-family listening

The client MUST accept inbound ed2k TCP and UDP over both IPv4 and IPv6 when both
are available, and MUST continue operating on a single family when the other is
unavailable.

#### Scenario: Both families available

- GIVEN a host with a routable IPv4 address and a routable IPv6 address
- WHEN the client starts
- THEN it MUST accept inbound connections on both families on the configured port
- AND both MUST be reported in the connection state

#### Scenario: IPv6 unavailable

- GIVEN a host with no routable IPv6 address
- WHEN the client starts
- THEN IPv4 operation MUST be unaffected
- AND the failure to bind IPv6 MUST be logged once, not per retry

#### Scenario: Dual-stack socket unsupported by the platform

- GIVEN a platform that rejects a dual-stack listening socket
- WHEN the client starts
- THEN it MUST fall back to one listening socket per family
- AND MUST NOT report itself unreachable while either socket is listening

### Requirement: Family-aware outbound connection

Outbound connections MUST select the address family from the target endpoint, and
MUST fall back to the other family when the peer is reachable on both and the
first attempt fails.

#### Scenario: Peer reachable on both families

- GIVEN a peer advertising both an IPv4 and an IPv6 address
- WHEN the IPv6 attempt fails at connect time
- THEN the client MUST attempt the IPv4 address
- AND the peer MUST NOT be marked dead until both have failed

### Requirement: IPv6 in the IP filter

The IP filter MUST evaluate IPv6 addresses, and MUST treat an IPv4-mapped IPv6
address as its IPv4 form for filtering purposes.

#### Scenario: Filtered IPv4 peer arriving mapped

- GIVEN an IPv4 range that the filter blocks
- WHEN a connection arrives from the IPv4-mapped IPv6 form of an address in that range
- THEN the connection MUST be blocked
- AND the block MUST be attributed to the matching IPv4 rule

#### Scenario: IPv6 range rule

- GIVEN a filter list containing an IPv6 prefix
- WHEN a peer inside that prefix connects
- THEN the connection MUST be blocked

### Requirement: IPv6 reachability advertisement

The client MUST advertise IPv6 reachability only when it has verified inbound
IPv6 connectivity, using the `SupportsIPv6` capability bit together with
`CT_MOD_IP_V6` and the `"ip6"` tag.

#### Scenario: IPv6 bound but not reachable

- GIVEN the client has bound an IPv6 socket but has received no inbound IPv6 connection
- WHEN it builds a hello packet
- THEN it MUST NOT claim verified IPv6 reachability
- AND it MAY still include its IPv6 address for peers to attempt
