# ADR-024: Persist peer message acknowledgement heads

## Status

Accepted

## Date

2026-10-04

## Context

The conversation must distinguish a message saved only on the sender from one
accepted by another device without implying server-style permanent delivery.
An inserted-event count is insufficient because an idempotent retry can accept
an event while reporting zero new inserts.

## Decision

After a complete authenticated push session, store the highest contiguous
author sequence accepted by that peer. Keep one monotonic head per group, peer,
and author. Derive `local` and `sharedWithPeer` display states from that durable
head. Do not advance it after a partial or failed session.

## Consequences

- A successful idempotent retry still proves that the peer accepted the event.
- Delivery state survives restart and never moves backwards.
- `sharedWithPeer` means at least one peer accepted the message.
- Observation by every known member requires separate per-member receipts.
