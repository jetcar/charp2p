# ADR-013: Protected issued invitations

## Status

Accepted

## Date

2026-09-30

## Context

An owner must retain each invitation's discovery secret while it remains valid
so the client can advertise the matching rendezvous key and display the same
link after restart. The signed invitation is a bearer credential. Storing it in
the ordinary SQLite application database would expose join authority in routine
database copies and diagnostics.

## Decision

Store each encoded issued invitation in the platform keyring under its random
16-byte invitation identifier. Limit protected records to 2 KiB and wrap bytes
from the keyring in zeroizing memory before UTF-8 and signature validation.

Store only the invitation identifier, group identifier, and expiry in the
versioned SQLite index. On every load, revalidate the protected invitation and
require all indexed fields to match its signed claims. Remove expired records
from both stores. If protected storage is missing after an interrupted write,
remove its incomplete SQLite index.

Create the SQLite index first while holding the shared protected-storage lock,
then write the bearer credential. Roll back the index if the protected write
fails. Return the custom application URI to the owner interface so it can be
copied and shared. The current single-group shell permits one active issued
invitation so an older bearer credential cannot become hidden from its UI.

Before admitting a join request, the owner revalidates the presented bearer
signature and expiry, requires its group to match the request and a locally
protected group root, finds the invitation in the SQLite issue index, and
compares it with the exact protected bearer record. Wire-shape validation alone
does not authorize membership. This check proves current local issuance but does
not consume a single-use invitation; reuse and revocation are enforced by the
signed membership state when the member-add event is committed.

## Consequences

- Issued links and discovery secrets survive application restarts without
  entering the ordinary SQLite database.
- A database copy reveals invitation timing and group association but cannot
  reconstruct the bearer link.
- Generating a replacement does not revoke an older invitation. Revocation
  remains a signed group event and must remove the corresponding protected
  record when that event is applied.
- Owner-side DHT advertising consumes the protected invitation after the same
  signature and index validation.
- The join handshake now has a local issuance authorization boundary. MLS
  admission and atomic single-use consumption remain separate increments.
