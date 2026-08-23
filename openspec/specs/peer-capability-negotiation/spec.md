# peer-capability-negotiation

## Requirements

### Requirement: Vendor capability tag round-trip

The client MUST parse the `CT_MOD_*` vendor tag family from peer hello and
handshake packets, and MUST emit only those tags whose underlying feature it
implements.

#### Scenario: Peer advertises IPv6 and QUIC

- GIVEN a peer hello carrying `CT_MOD_IP_V6` (`0xAE`) and a misc-options word with bits 2 and 4 set
- WHEN the client parses the handshake
- THEN the peer record MUST record IPv6 and QUIC NAT-T as peer-supported
- AND the client MUST NOT set either bit in its own reply until the corresponding feature ships

#### Scenario: Unknown vendor tag

- GIVEN a peer hello carrying a `CT_MOD_*` tag the client does not recognise
- WHEN the client parses the handshake
- THEN the tag MUST be ignored
- AND the handshake MUST continue as if the tag were absent

### Requirement: Misc-options bit order

The misc-options bitfield MUST use the exact bit positions of eMuleAI's
`UModMiscOptions`: bit 0 extended source exchange, bit 1 legacy uTP NAT-T,
bit 2 IPv6, bit 3 serving-buddy pull, bit 4 QUIC NAT-T. Bits 5 and above are
reserved and MUST be transmitted as zero.

#### Scenario: Reserved bits set by peer

- GIVEN a peer sends a misc-options word with bit 7 set
- WHEN the client parses it
- THEN the reserved bits MUST be masked off and ignored
- AND no capability MUST be inferred from them

#### Scenario: Bit order regression

- GIVEN the unit test fixture encoding all five known capability bits
- WHEN the encoder and decoder round-trip the fixture
- THEN each decoded flag MUST match its documented bit position exactly

### Requirement: Reserved-protocol frame demultiplexing

`OP_UDPRESERVEDPROT2` payloads MUST be dispatched on their first byte as a frame
type. Types `0x00` uTP, `0x01` QUIC, `0x02` capability, `0x03` capability ack and
`0xFF` key MUST be recognised. Unrecognised types MUST be dropped.

#### Scenario: Frame type the client cannot handle

- GIVEN an inbound `OP_UDPRESERVEDPROT2` datagram with frame type `0x01`
- WHEN the client has no QUIC transport
- THEN the datagram MUST be dropped without error
- AND the sender MUST NOT be counted toward any flood or ban threshold

#### Scenario: Truncated frame

- GIVEN an `OP_UDPRESERVEDPROT2` datagram with an empty payload
- WHEN the client attempts to read the frame type
- THEN the datagram MUST be dropped
- AND the read MUST NOT access memory past the payload end
