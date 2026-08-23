# kademlia

## Requirements

### Requirement: Protocol version advertisement

The Kademlia implementation MUST advertise version `0x0a` and MUST remain
interoperable with peers advertising `0x08` and `0x09`.

#### Scenario: Peer at an older version

- GIVEN a contact advertising Kad version `0x08`
- WHEN the client stores keyword entries for that contact
- THEN AICH hash storage MUST be omitted for it
- AND the contact MUST remain usable for search and routing

#### Scenario: Keyword storage at 0x09 or above

- GIVEN a publishing peer advertising version `0x09` or higher
- WHEN it publishes a keyword entry carrying an AICH hash
- THEN the hash MUST be stored with the entry
- AND MUST be returned in search results to peers at `0x09` or higher

### Requirement: Adaptive response-time ceiling

The client MUST derive its Kad request timeout from observed response times
rather than a fixed constant, using a bounded sample window.

#### Scenario: Slow network

- GIVEN a sample window whose observed response times rise steadily
- WHEN the estimator recomputes the ceiling
- THEN the effective timeout MUST rise with the observed distribution
- AND MUST stay within a documented absolute maximum

#### Scenario: Cold start

- GIVEN fewer than two recorded samples
- WHEN a request timeout is required
- THEN the client MUST fall back to the documented default
- AND MUST NOT divide by a zero sample count

### Requirement: Identity-change rate limiting

A tracked node address MUST NOT be accepted with a changed Kad ID more than once
per hour. Nodes violating this MUST be treated as problematic.

#### Scenario: Rapid identity rotation

- GIVEN a node address that presented ID A less than one hour ago
- WHEN the same address presents ID B
- THEN the contact MUST be rejected from the routing table
- AND the address MUST be added to the problematic list

#### Scenario: Legitimate change after the interval

- GIVEN a node address whose last ID change was more than one hour ago
- WHEN it presents a new ID
- THEN the contact MUST be accepted subject to the existing verification checks

### Requirement: Bounded protection state

Every protection table MUST be bounded and MUST evict by last-reference age:
tracked nodes 10000, problematic nodes 10000, banned addresses 1000.

#### Scenario: Table at capacity

- GIVEN the tracked-node table holds 10000 entries
- WHEN a new node must be tracked
- THEN the least-recently-referenced entry MUST be evicted first
- AND memory use MUST NOT grow with sustained inbound traffic

#### Scenario: Ban expiry

- GIVEN an address banned more than four hours ago
- WHEN it is next evaluated
- THEN the ban MUST have lapsed
- AND the address MUST be evaluated on its current behaviour alone
