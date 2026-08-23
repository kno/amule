# Delta for transport-utp

## ADDED Requirements

### Requirement: uTP shares the ed2k UDP port

uTP traffic MUST be sent and received on the same UDP port the client already
uses for ed2k UDP, and MUST NOT require a second port to be opened or forwarded.

#### Scenario: Inbound datagram classification

- GIVEN an inbound datagram on the ed2k UDP port
- WHEN it is a uTP packet
- THEN it MUST be delivered to the uTP context
- AND MUST NOT reach the ed2k UDP parser

#### Scenario: Non-uTP datagram

- GIVEN an inbound datagram on the same port that the uTP context declines
- WHEN classification completes
- THEN the datagram MUST continue to the ed2k UDP parser unmodified

### Requirement: uTP timer processing

The uTP context MUST be driven by a periodic tick independent of traffic.

#### Scenario: Idle connection with pending retransmission

- GIVEN an established uTP connection with unacknowledged data and no inbound traffic
- WHEN the tick interval elapses
- THEN retransmission MUST occur
- AND the connection MUST NOT stall waiting for an inbound packet to drive it

### Requirement: Write buffering with duplex awareness

Application writes MUST be buffered when the uTP window is closed. The buffer
MUST grow on sustained blocking at capacity and MUST shrink when the connection
is carrying traffic in both directions.

#### Scenario: Simultaneous upload and download

- GIVEN one uTP connection transferring in both directions
- WHEN both directions are active
- THEN the write buffer MUST be trimmed toward the duplex capacity
- AND neither direction MUST stall for lack of buffer

#### Scenario: Sustained blocked writes

- GIVEN repeated write attempts that block with the buffer at capacity
- WHEN the blocked-write count crosses the growth threshold
- THEN the buffer MUST grow up to the documented maximum
- AND growth MUST stop at that maximum rather than growing unbounded

### Requirement: The uTP capability bit follows the ability to serve

The `MOD_MISCOPT_NAT_TRAVERSAL` bit (bit 1, `0x00000002`) in the
`CT_MOD_MISCOPTIONS` (`0xAA`) handshake tag MUST be set only when this client can
serve a uTP connection, meaning a uTP context exists AND an inbound uTP
connection attempt on it would be handled rather than dropped. Having the uTP
transport compiled in MUST NOT by itself set the bit. When the resulting
capability word is zero, the tag MUST NOT be emitted and MUST NOT be counted in
the handshake tag count.

#### Scenario: uTP compiled in but unable to serve

- GIVEN a build configured with the uTP transport and a uTP context
- WHEN the inbound accept path is not wired, so an inbound uTP attempt would be dropped
- THEN the advertised capability word MUST NOT contain `MOD_MISCOPT_NAT_TRAVERSAL`
- AND no `CT_MOD_MISCOPTIONS` tag MUST be emitted

#### Scenario: uTP able to serve

- GIVEN a uTP context whose inbound accept path is wired
- WHEN the handshake is sent
- THEN the advertised capability word MUST contain `MOD_MISCOPT_NAT_TRAVERSAL` (`0x00000002`)
- AND the `CT_MOD_MISCOPTIONS` tag MUST be emitted and counted

### Requirement: Transport failure is distinct from peer refusal

A failed uTP establishment MUST be reported as a transport failure, separately
from a peer-level connection refusal.

#### Scenario: uTP blocked by an intermediate network

- GIVEN a peer that is reachable over TCP but whose uTP handshake never completes
- WHEN the uTP attempt times out
- THEN the client MUST fall back to TCP for that peer
- AND the peer MUST NOT be marked dead or removed from the source list
