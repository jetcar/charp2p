# ADR-033: Device-local client synchronization data limit

## Status

Accepted

## Date

2026-10-06

## Context

The Settings page offers bandwidth limits (product design, page 10). Contribution
traffic already has its own explicit limits on the Network page (ADR-031). A
member device synchronizes with its group owner by pulling missing signed
events and pushing its own (ADR-006). Each response is bounded to 2 MiB of
event payload, but a device that rejoins after a long absence, or that runs
on a metered connection, has no way to cap how much synchronization data it
transfers.

## Decision

The application offers an optional, device-local synchronization data limit
in MiB per hour, from 1 to 1024 MiB. It is off by default, held in a small
JSON file next to the database, holds no secrets and is not synchronized. A
missing file means no limit; an unreadable or invalid file is reported on the
Settings page and synchronization does not start until the preference is
corrected, so an invalid file never lifts a limit the user set.

The limit is enforced as a token bucket whose capacity is one hour of the
limit and which refills continuously. It counts the encoded signed event
bytes this device requests, receives and pushes during client
synchronization. Before each synchronization exchange the device checks that
budget remains; an exchange that is already sent completes and its bytes are
charged, so a single exchange may overshoot the limit by at most one bounded
response. Synchronization that finds the budget spent stops and reports a
waiting state; pulls resume from stored heads on the next attempt.

The limit covers client synchronization only. Peer discovery, the bounded
join exchange and the first pull that completes a join, owner answers to member requests and contribution traffic
(ADR-031) are not counted. The budget is held in memory and starts full when
the application starts.

## Consequences

- Users on metered connections can bound synchronization volume, at the cost
  of slower catch-up after long absences.
- Protocol framing, transport and discovery overhead are not counted, so the
  limit is an application-level bound, not an exact network meter.
- Restarting the application refills the budget.

## Sources

- docs/product-design.md, page 10
- ADR-006, ADR-031
