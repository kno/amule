# Delta for network-addressing

## ADDED Requirements

### Requirement: Family-agnostic address representation

The internal address type MUST represent both IPv4 and IPv6 addresses, MUST
preserve the distinction between an IPv4 address and its IPv4-mapped IPv6 form,
and MUST provide a total ordering suitable for use as a map key.

#### Scenario: Mapped and native forms compared

- GIVEN the IPv4 address `192.0.2.1` and its mapped form `::ffff:192.0.2.1`
- WHEN both are stored and compared
- THEN the type MUST report whether each is mapped
- AND equality MUST follow one documented rule applied consistently at every call site

#### Scenario: Use as a container key

- GIVEN a set of mixed IPv4 and IPv6 addresses
- WHEN they are inserted into an ordered container
- THEN ordering MUST be total and stable across runs
- AND no two distinct addresses MUST compare equal

### Requirement: Explicit byte order at conversion boundaries

Every conversion between the address type and a 32-bit integer MUST state its
byte-order expectation in its signature.

#### Scenario: Kad boundary conversion

- GIVEN a Kad routing call that requires a network-order 32-bit address
- WHEN an internal address is converted for it
- THEN the conversion used MUST be the network-order variant named as such
- AND a host-order value MUST NOT be accepted by that signature

#### Scenario: IPv6 address at a 32-bit boundary

- GIVEN an IPv6 address that is not IPv4-mapped
- WHEN conversion to a 32-bit integer is attempted
- THEN the conversion MUST fail explicitly
- AND MUST NOT truncate, hash, or otherwise fabricate a 32-bit value

### Requirement: Distinguishable unspecified address

The type MUST distinguish "no address" from "the all-zero address".

#### Scenario: Absent address

- GIVEN a client record with no known address
- WHEN the address is read
- THEN the absence MUST be representable without using the all-zero address
- AND code paths that previously tested against zero MUST test absence explicitly

### Requirement: Socket backend family independence

The Asio backend MUST NOT hardcode an address family. Listener and outbound
socket creation MUST derive the family from configuration or from the target
address.

#### Scenario: Outbound connection to an IPv6 peer

- GIVEN a peer endpoint that is IPv6
- WHEN an outbound socket is created for it
- THEN the socket MUST be opened in the IPv6 family
- AND no `v4()`-pinned code path MUST be reachable for it
