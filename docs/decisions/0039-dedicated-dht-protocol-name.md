# ADR-039: Dedicated Kademlia protocol name

## Status

Accepted

## Date

2026-10-08

## Context

CharP2P uses a dedicated, open libp2p-compatible discovery network (technical
design, Discovery). The Kademlia behaviour was configured with the libp2p
default protocol name `/ipfs/kad/1.0.0`, which is shared with the public IPFS
DHT. A CharP2P node connected to an IPFS peer, or an IPFS peer reaching a
CharP2P serving node, would treat the other as a routing peer: CharP2P
provider records could be stored on IPFS nodes outside the serving-node
filters of ADR-009, and IPFS traffic could fill CharP2P routing tables and
serving-node stores.

## Decision

All CharP2P nodes speak Kademlia only under the protocol name
`/charp2p/kad/1.0.0`. Client, contribution and standalone serving nodes use the
same name, so they keep routing to each other; peers that support only the
IPFS name are not added to the CharP2P routing table and receive no CharP2P
queries or provider records. The wire format stays the unmodified libp2p
Kademlia protocol, so community nodes can still be built from any compatible
libp2p implementation. An incompatible change to the DHT messages or record
rules uses a new protocol version.

## Consequences

- The CharP2P DHT is a separate network; discovery keys are only advertised to
  and searched on CharP2P nodes.
- Nodes built before this change cannot route with newer nodes. The project has
  not deployed public nodes yet, so no migration is needed.
- Generic IPFS tooling can no longer inspect the CharP2P DHT without being
  configured with the CharP2P protocol name.

## Sources

- docs/technical-design.md, Discovery
- ADR-005, ADR-009
- https://github.com/libp2p/specs/tree/master/kad-dht
