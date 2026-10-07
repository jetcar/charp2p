# ADR-035: Device-local message retention

## Status

Accepted

## Date

2026-10-07

## Context

The Settings page offers local retention (product design, page 10). Readable
message copies otherwise stay on a device until the user hides them one by one
(ADR-023) or leaves the group (ADR-027). Removing signed events by age would
break synchronization summaries and the history other members pull, and a
group-wide retention rule would need a signed, owner-authorized policy that the
MVP does not define.

## Decision

The application offers an optional, device-local retention period in whole
days, from 1 to 3650. It is off by default, held in a small JSON file next to
the database, holds no secrets and is not synchronized. A missing file keeps
every message; an unreadable or invalid file is reported on the Settings page
and nothing is removed until the preference is corrected, so a damaged file
never removes messages under a guessed period.

Retention reuses device-local deletion (ADR-023): every materialized message
whose signed creation time is older than the period is removed from the
readable message table, its unread marker is cleared and its event ID is added
to the hidden-message table, in one SQLite transaction across all groups. The
verified signed events are kept. Retention is applied when the preference is
saved and before messages or unread counts are listed, so a message
synchronized later with an old creation time is removed before it is shown.

## Consequences

- Retention affects only this device; other members keep their copies.
- Synchronization, sequence checks and evidence of signed envelopes still work
  for removed messages; their readable text cannot be recovered locally.
- Retention uses the author-supplied creation time, so a message with a
  future-dated timestamp stays until that time passes the period.
- The small encrypted signed events are not reclaimed, as with ADR-023.
- A group-wide or owner-set retention policy remains future work.
