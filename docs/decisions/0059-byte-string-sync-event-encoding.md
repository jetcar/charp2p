# ADR-059: Byte-string encoding of synchronized events

## Status

Accepted

## Date

2026-10-19

## Context

ADR-006 carries synchronization messages as CBOR and bounds each encoded
request and response at 2.125 MiB while allowing 2 MiB of signed event data per
batch. The serde derive wrote each encoded event as a CBOR array of integers,
which spends two bytes on most byte values. Signatures, identifiers and MLS
ciphertext are close to random, so a valid batch above about 1.1 MiB of event
data exceeded the wire bound. The receiver stopped reading at the bound and the
exchange failed on every retry, stalling that author's history and any upload
that rebuilt the same batch.

## Decision

`PushEvents` requests and `Events` responses encode each signed event as a CBOR
byte string, which adds at most a few bytes of length prefix per event. A full
batch of 256 events and 2 MiB of event data therefore fits the 2.125 MiB wire
bound. Because the encoding changes, the protocol becomes
`/charp2p/sync/3.0.0`; the limits of ADR-006 are unchanged.

## Consequences

- Batches up to the documented event-data limit are delivered in one exchange.
- Peers running `/charp2p/sync/2.0.0` cannot synchronize with updated peers;
  both sides need the same release, as for any earlier protocol version.
- Event identifiers and other fields keep their existing encoding; their size
  is far below the 128 KiB of wire headroom.
