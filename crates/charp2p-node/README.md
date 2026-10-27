# CharP2P routing node

`charp2p-node` is a standalone community bootstrap, Kademlia routing, and
Circuit Relay v2 node. It stores no group events or message payloads and
rejects synchronization, join, and invitation requests.

Relay service is bounded to 32 reservations, one reservation per peer, 32
simultaneous circuits, four circuits per peer, five minutes per circuit, and
32 MiB per circuit. An operator can lower those limits with
`--relay-max-circuits <1-32>` (`CHARP2P_NODE_RELAY_MAX_CIRCUITS`) and
`--relay-max-circuit-mib <1-32>` (`CHARP2P_NODE_RELAY_MAX_CIRCUIT_MIB`), or
offer DHT routing only with `--disable-relay` (`CHARP2P_NODE_DISABLE_RELAY=true`).
Values outside those bounds stop startup. The upstream per-peer and per-IP
relay reservation and circuit rate limits remain enabled.

Inbound connections are bounded to 128 pending and 1,024 established
connections, four established connections per peer, and 16 established direct
connections per remote IP address. Each peer may send a burst of 64 join,
invitation, or synchronization requests, refilled at eight per second, before
further requests are refused. Bytes read from direct TCP and QUIC connections
draw from two token buckets (ADR-050): per peer, a 4 MiB burst refilled at
1 MiB per second, and per remote IP address, a 16 MiB burst refilled at 4 MiB
per second. A read that exceeds either bucket waits for the refill, so the
remote side slows down instead of being buffered. Relayed connections are
bounded by the relay limits above. Production metrics, deployment packaging,
and load-tested quotas are later increments.

Run it with a persistent identity file:

```sh
cargo run --release -p charp2p-node -- \
  --listen /ip4/0.0.0.0/udp/4001/quic-v1 \
  --listen /ip6/::/udp/4001/quic-v1 \
  --listen-tcp /ip4/0.0.0.0/tcp/4001 \
  --listen-tcp /ip6/::/tcp/4001 \
  --identity /var/lib/charp2p/node-identity.key
```

The defaults are also available through environment variables:

```text
CHARP2P_NODE_LISTEN=/ip4/0.0.0.0/udp/4001/quic-v1
CHARP2P_NODE_LISTEN_TCP=/ip4/0.0.0.0/tcp/4001
CHARP2P_NODE_IDENTITY=data/node-identity.key
```

`--listen` and `--listen-tcp` may be repeated, and their environment variables
take several comma-separated addresses, for example to also accept IPv6
connections. Every address must be available or startup stops.

To join other routing nodes into one Kademlia DHT, pass their complete
addresses with `--bootstrap <multiaddr>/p2p/<peer-id>` (repeatable) or
comma-separated in `CHARP2P_NODE_BOOTSTRAP`. At most 16 addresses are
accepted, an address without a trailing peer ID stops startup, and the node's
own address is ignored. The node bootstraps at startup and again every five
minutes so it finds restarted peers; an unreachable bootstrap node only delays
routing.

To refuse abusive peers, list their peer IDs one per line in a text file and
pass it with `--blocked-peers <file>` or `CHARP2P_NODE_BLOCKED_PEERS`. Blank
lines and lines starting with `#` are ignored. The file is read at startup, is
limited to 256 KiB and 4,096 peer IDs, and an invalid line stops startup. On
Unix, send `SIGHUP` to re-read it without restarting: newly listed peers are
disconnected, which also ends their relay reservations and circuits, and peers
removed from the file may connect again. A reload that fails to read or parse
the file is reported and keeps the current list. `SIGTERM` and interrupt stop
the node. Blocked peers cannot connect, route through the DHT, or reserve relay
circuits on this node; the block does not affect other nodes or any group.

On Unix, a new identity file is created with mode `0600`; startup fails when an
existing identity is accessible by group or other users. Back up this file if
the node should keep the same peer ID.

Open the selected UDP and TCP ports in the host firewall. The node accepts
QUIC connections on the UDP address and Noise-authenticated TCP connections
on the TCP address (ADR-047). The process prints a multiaddress ending in
`/p2p/<peer-id>` for each listener. For local client development, assign
that complete address to `CHARP2P_BOOTSTRAP_NODES` before starting the app.
Multiple client bootstrap addresses are separated by semicolons.

The process logs only its peer ID, listen addresses, relay limits, the counts
of blocked peer identities and bootstrap nodes, blocked peer list reload
results (counts and errors), shutdown, coarse DHT operation failures, and
rejections that could not be delivered because the peer closed its stream. It
does not log discovery keys or connected peer IDs.
Relay operators can still observe source and destination peer metadata, timing,
and traffic volume; relayed peer streams remain end-to-end authenticated and
encrypted.

See [`docs/node-logging-retention.md`](../../docs/node-logging-retention.md)
for the complete data inventory and the retention policy for project-operated
nodes.
