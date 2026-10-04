# ADR-018: Expose only enforced MVP group options

## Status

Accepted

## Date

2026-10-04

## Context

The early group form exposed retained-history sharing, manual owner approval,
and single-use invitations before their protocol state transitions existed.
Presenting those controls would promise access restrictions the backend did not
enforce.

## Decision

The current secure group profile permits only:

- messages sent after a member joins;
- direct admission with a valid invitation; and
- reusable invitations bounded by signed expiry.

The UI describes those fixed semantics instead of offering inactive controls.
The backend rejects group creation requests for retained history, manual
approval, or single-use invitations.

## Consequences

- Displayed access and history behavior matches protocol enforcement.
- Existing protocol fields remain available for future versioned behavior.
- Adding an option requires its durable authorization or history mechanism
  before the control is exposed.
