# ADR-006: Bounded synchronization messages

## Status

Accepted

## Date

2026-09-28

## Context

Untrusted peers need to compare group event state and request missing signed
envelopes without allocating unbounded memory or trusting remote validation.
Events can arrive out of order, so a maximum author sequence alone cannot show
that all earlier events are present.

## Decision

Use a versioned request-response synchronization protocol with three exchanges:

1. Request gap-free author heads for one group.
2. Request up to 256 ordered event identifiers after an author sequence.
3. Request canonical signed envelopes for selected identifiers.

Carry these messages as CBOR over the libp2p stream protocol
`/charp2p/sync/1.0.0`. Limit encoded requests to 64 KiB, encoded responses to
2.125 MiB, each request to 30 seconds, and each connection to 32 concurrent
synchronization streams.

Limit summaries to 1,024 authors, identifier and event pages to 256 items, each
encoded event to 128 KiB, and combined event payloads to 2 MiB. Reject duplicate
authors and event IDs. Verify every event signature and group ID before exposing
an event response to persistence.

Authorization remains a separate group-state check. An unauthorized request is
rejected without revealing whether the requested group exists.

After authorization, a synchronization engine builds responses from verified
SQLite events. Incoming event responses are validated as a whole and committed
in one transaction so sequence conflicts cannot leave a partial batch.

A pull session processes one peer sequentially: summary, event-ID page, event
batch, then the next page or author. It detects mismatched responses and peers
that advertise history but fail to advance the local gap-free sequence.

## Consequences

- Missing sequence gaps cannot be mistaken for synchronized history.
- Large histories transfer through resumable bounded pages.
- Invalid signed envelopes fail the entire response before any are committed.
- A peer may return fewer events than requested to remain under the byte cap.

## Sources

- https://github.com/libp2p/specs/tree/master/reqres
- https://docs.rs/libp2p-request-response/0.30.0
