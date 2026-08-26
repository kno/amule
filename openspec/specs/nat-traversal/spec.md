# nat-traversal

## Requirements

### Requirement: Rendezvous relay validation

A client acting as a rendezvous relay MUST validate that the endpoint hint in an
`OP_RENDEZVOUS` request corresponds to the address the request arrived from, and
MUST rate-limit relaying per requester.

#### Scenario: Endpoint hint naming a third party

- GIVEN a rendezvous request arriving from address X
- WHEN its endpoint hint names an unrelated address Y
- THEN the request MUST be discarded
- AND no packet MUST be sent toward Y as a result

#### Scenario: Relay flooding

- GIVEN a requester that has exceeded its relay rate limit
- WHEN it sends a further rendezvous request
- THEN the request MUST be discarded
- AND the requester MAY be subject to existing flood accounting

### Requirement: Bounded rendezvous attempts

A rendezvous MUST be bounded at 5 attempts and 120 seconds total. On exhaustion
the source MUST be marked temporarily unreachable and retried after a 60 second
backoff.

#### Scenario: Traversal never converges

- GIVEN two peers whose NAT mappings prevent convergence
- WHEN 5 attempts have failed or 120 seconds have elapsed
- THEN the client MUST stop punching for that pair
- AND MUST fall back to server callback or Kad buddy if available

#### Scenario: Source retained across failure

- GIVEN a rendezvous that has just exhausted its budget
- WHEN the backoff period is in effect
- THEN the source MUST remain queued
- AND MUST NOT be deleted or counted as a dead source

#### Scenario: Success before exhaustion

- GIVEN a hole punch that succeeds on the third attempt
- WHEN the connection is established
- THEN remaining attempts MUST be cancelled
- AND no further hole-punch packets MUST be sent for that pair

### Requirement: Endpoint hints are advisory

An endpoint hint MUST be treated as one candidate address, never as a replacement
for addresses already known for the peer.

#### Scenario: Incorrect self-reported endpoint

- GIVEN a peer behind symmetric NAT whose hint reports a stale external port
- WHEN traversal is attempted
- THEN the client MUST also attempt the endpoints it already knows
- AND MUST NOT discard known-good addresses in favour of the hint

### Requirement: Capability-gated traversal

Traversal MUST only be attempted with peers that advertised the corresponding
capability bit, and MUST fall back to the legacy uTP frame type when the QUIC
capability is absent after the documented 1500 ms wait.

#### Scenario: Peer without traversal support

- GIVEN a peer advertising no NAT traversal capability
- WHEN the client needs a connection to it and both are firewalled
- THEN no rendezvous MUST be initiated
- AND the existing callback and buddy paths MUST be used
