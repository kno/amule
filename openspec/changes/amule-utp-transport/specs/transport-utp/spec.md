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

### Requirement: Transport failure is distinct from peer refusal

A failed uTP establishment MUST be reported as a transport failure, separately
from a peer-level connection refusal.

#### Scenario: uTP blocked by an intermediate network

- GIVEN a peer that is reachable over TCP but whose uTP handshake never completes
- WHEN the uTP attempt times out
- THEN the client MUST fall back to TCP for that peer
- AND the peer MUST NOT be marked dead or removed from the source list
