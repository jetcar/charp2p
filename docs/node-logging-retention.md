# Routing node logging and retention

This policy applies to the standalone `charp2p-node` binary and to
project-operated instances of it. It describes the current implementation;
deployment changes that collect more data must update this document before
public traffic is accepted.

## Persistent data

The node writes only its libp2p Ed25519 identity file. Keeping this file keeps
the node's public peer ID stable across restarts. The file is versioned, limited
to 512 bytes, and created with mode `0600` on Unix. Startup rejects an existing
identity file that is accessible to group or other users.

An optional blocked-peer file is operator-managed input. The node reads it but
does not write it. It is limited to 256 KiB and 4,096 unique peer IDs.

The node does not persist DHT records, routing tables, relay state, group
events, messages, invitations, or synchronization requests.

## In-memory retention

All network state is lost when the process stops.

- Provider records use an in-memory store, expire after 30 minutes, and are
  bounded to 1,024 keys, 20 providers per key, and 8 addresses per provider.
- Relay reservations expire after one hour. Relay circuits expire after five
  minutes or when their configured byte limit is reached.
- Connections, routing-table entries, request rate limits, and bandwidth
  buckets exist only while the process runs or the associated connection is
  active.

The node rejects group join, invitation, and synchronization requests. It
therefore does not retain group content while handling them.

## Built-in logs

The binary writes operational messages to standard output and standard error.
It does not create, rotate, or retain log files itself.

It logs:

- its own public peer ID and listening multiaddresses;
- configured relay limits, bootstrap-node count, and blocked-peer count;
- aggregate blocked-peer reload counts and reload errors;
- startup, shutdown, and coarse DHT operation failures; and
- failures to deliver a rejection because the remote stream closed.

It does not log:

- message content, group events, group IDs, or discovery keys;
- invitation payloads or synchronization request bodies;
- remote peer IDs, remote IP addresses, or connection traffic; or
- DHT provider records or relay source and destination identities.

Operators can still observe connection metadata with host, firewall, reverse
proxy, or packet-capture tooling. Such tooling is outside the node and must not
be enabled by default for a project-operated deployment.

## Project-operated deployment policy

Project-operated nodes collect the built-in output only. The log collector
must use rolling deletion with a maximum retention of seven days, encrypt logs
at rest and in transit, and limit access to operators responsible for node
availability and abuse response. Backups must not extend the retention period.
Logs must not be used for advertising, profiling, or tracking group activity.

An incident export may be preserved beyond seven days only when needed to
investigate a specific security or abuse event. It must be access-restricted,
record its reason and deletion date, and be deleted within 90 days unless a
legal preservation duty applies.

Before enabling new metrics or more verbose logging, review every field for
peer IDs, IP addresses, discovery keys, group identifiers, invitation data,
and message data. Update this policy and the published privacy information
before collection begins.

## Operator checklist

- Keep the identity file outside log and backup bundles unless the backup is
  specifically intended to preserve the node identity.
- Restrict the identity and blocked-peer files to the node account.
- Configure the stdout/stderr collector for a seven-day maximum retention.
- Do not enable packet capture or connection-level access logs by default.
- Verify deletion and access controls before accepting public traffic.
