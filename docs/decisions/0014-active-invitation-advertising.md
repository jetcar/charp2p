# ADR-014: Active invitation advertising

## Status

Superseded in part by ADR-025

## Date

2026-09-30

## Context

A joiner can find a group only while at least one peer provides the opaque
rendezvous key derived from its invitation. A completed `start_providing`
operation is insufficient by itself because the libp2p swarm must continue to
run to answer connections and maintain the provider record.

## Decision

After an issued invitation is restored from protected storage and revalidated,
start one background libp2p advertiser for its rendezvous key. Keep the swarm
polled until the invitation's signed expiry. Refresh the provider publication
every five minutes; end a task whose refresh fails so the client status poll
can restart it. Reuse an active task for the same key and expiry, and abort it
before replacing it with another advertisement.

Require a configured bootstrap peer before starting. Report
`bootstrapRequired` to the interface when none is available. Treat successful
Kademlia provider publication as the point at which the interface may report
the invitation as advertising. Reject synchronization requests received by the
advertiser until a later join protocol has authenticated and authorized the
requesting device.

## Consequences

- The owner is discoverable while the application and advertiser are running.
- The interface checks the advertiser every 30 seconds and retries failed
  startup after five seconds.
- Provider records may remain visible until the DHT TTL after the owner closes
  the application, but no process remains to accept a connection.
- The advertiser rechecks signed wall-clock expiry every second, bounding
  clock-correction detection delay to one second.
- Join authorization and invitation revocation remain separate protocol work.
- Discovery alone grants no event synchronization access.
