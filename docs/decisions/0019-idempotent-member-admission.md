# ADR-019: Make member admission idempotent

## Status

Accepted

## Date

2026-10-04

## Context

An owner can commit an MLS member addition and lose the connection before the
joining device receives its Welcome. Retrying the same request must not create
a second leaf for that device or leave the device permanently unable to join.

## Decision

The owner hashes the bounded KeyPackage and atomically stores that hash, the
signed `MemberAdded` event, the advanced encrypted MLS provider snapshot, and
an encrypted copy of the accepted join response. The cached response is bound
to the group, authenticated device, and request hash with authenticated
encryption.

An exact retry returns the original response, including after owner restart. A
different KeyPackage for an already admitted device is rejected.

## Consequences

- Lost responses do not create duplicate MLS members.
- Admission completion remains recoverable after owner restart.
- Cached Welcomes are protected by the same platform wrapping key as MLS state.
- Replacing a device KeyPackage requires a future signed device-replacement or
  revocation flow.
