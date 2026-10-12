# ADR-054: Record invitation provenance to retire unused rendezvous keys

## Status

Accepted

## Date

2026-10-12

## Context

ADR-025 keeps every owner-side rendezvous key after its bearer invitation
expires or is revoked, so admitted members can rediscover the owner, and
bounds retained keys to 64 per group. Without knowing which invitation
admitted which device, the owner cannot tell a key that admitted members still
use from one that admitted nobody, so a group stops accepting new invitations
after 64 have ever been issued. ADR-025 left selective retirement to
membership-to-invitation provenance.

## Decision

The owner records, in the same SQLite transaction as each admission, the
invitation ID whose join request it answered. Admission through an
invitation requires that invitation's rendezvous-key index to be present in
that transaction, so an admission cannot commit after its key was retired.

After its bearer invitation has expired, been revoked or been retired as
consumed, an owner rendezvous key is retired when no current admission
records that invitation. Retirement removes the non-secret index in one
conditional statement before the protected key, so a concurrent admission
either commits first and keeps the key or is refused. Removing a member drops
its admission record, so a key whose admitted devices were all removed becomes
retireable too.

Keys indexed before provenance was recorded are kept as in ADR-025, since an
earlier admission through them cannot be ruled out.

## Consequences

- The 64-key bound counts keys of active invitations and keys that admitted a
  current member, rather than every invitation the group ever issued.
- A device holding an expired or revoked bearer that admitted nobody no longer
  learns the owner's reachability once the key is retired.
- A removed device that is later allowed to join again (ADR-034) needs a new
  active invitation, as before.
- Groups upgraded from earlier versions keep their pre-existing keys toward the
  bound; only keys indexed after the upgrade can be retired.

## Sources

- docs/decisions/0025-retained-owner-rendezvous-keys.md
- docs/decisions/0042-owner-consumed-single-use-invitations.md
- docs/technical-design.md (Discovery)
