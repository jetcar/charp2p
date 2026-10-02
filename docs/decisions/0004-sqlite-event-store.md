# ADR-004: SQLite for verified local events

## Status

Accepted

## Date

2026-09-28

## Context

Windows and Android clients need durable, transactional storage for verified
events. Repeated peer delivery must be idempotent, while reuse of one author
sequence for different event content must be detected before synchronization
state advances.

Cryptographic key material has different security requirements and must remain
in platform-protected storage rather than the event database.

## Decision

Use SQLite through `rusqlite` for the local verified-event index. Store each
canonical signed envelope once by event ID and enforce a unique constraint on
group, author, and author sequence.

Re-verify envelopes when reading them from storage. Use strict SQLite tables,
explicit schema versions, transactional writes, foreign-key enforcement, and a
bundled SQLite build for consistent desktop and Android behavior.

Build synchronization summaries from each author's highest gap-free sequence.
Expose event identifiers after a sequence in ordered pages capped at 256, and
verify signed envelopes before their identifiers leave the store.

Keep plaintext identity and group key material outside SQLite. SQLite may hold
one bounded, atomically replaced MLS provider ciphertext; its authenticated
encryption key remains in platform-protected storage and the store never
interprets the encrypted bytes. When a signed event advances MLS state, insert
the event and replace the resulting provider ciphertext in one SQLite
transaction so neither state can become durable alone.

SQLite also indexes one bounded public MLS KeyPackage per pending group join.
Creating that record and storing the encrypted provider snapshot containing its
matching private material is atomic. Completing the join atomically removes the
public KeyPackage record and replaces the provider snapshot with the joined
group state.

After MLS completion, atomically move authenticated non-secret invitation
metadata from the pending-invitation table into a joined-group table. Delete
the protected bearer credential after that durable transition. If protected
storage cleanup fails, a later completion or joined-group load retries it
without repeating the MLS exchange.

## Alternatives considered

### Flat event files

Simple to append, but require custom indexing, crash recovery, compaction, and
sequence-conflict handling.

### Embedded key-value store

Efficient for event IDs, but synchronization also needs ordered group/author
sequence queries and transactional secondary indexes.

### Store keys with events

Operationally simple, but exposes long-lived private keys to ordinary database
backup and diagnostic workflows.

## Consequences

- Duplicate delivery is an inexpensive no-op.
- Sequence conflicts are durable integrity failures rather than UI-level
  deduplication.
- Schema changes require migrations and compatibility tests.
- Database encryption at rest is separate from end-to-end payload protection.
- MLS provider ciphertext replacement is atomic and preserves the previous
  record when a new value fails local size validation.
- An event that advances MLS state and its resulting encrypted provider
  snapshot commit or roll back together.
- Pending join KeyPackages cannot become durable without their matching private
  material, and completed joins cannot lose one side of the state transition.
- Joined groups survive invitation expiry and restart without retaining the
  bearer credential as their display record.

## Sources

- https://docs.rs/rusqlite/0.40.2
- https://www.sqlite.org/stricttables.html
- https://www.sqlite.org/lang_transaction.html
