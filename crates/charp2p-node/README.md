# CharP2P routing node

`charp2p-node` is a standalone community bootstrap, Kademlia routing, and
Circuit Relay v2 node. It stores no group events or message payloads and
rejects synchronization requests.

Relay service is bounded to 32 reservations, one reservation per peer, 32
simultaneous circuits, four circuits per peer, five minutes per circuit, and
32 MiB per circuit. The upstream per-peer and per-IP request rate limits remain
enabled. Production metrics, deployment packaging, and load-tested quotas are
later increments.

Run it with a persistent identity file:

```sh
cargo run --release -p charp2p-node -- \
  --listen /ip4/0.0.0.0/udp/4001/quic-v1 \
  --identity /var/lib/charp2p/node-identity.key
```

The defaults are also available through environment variables:

```text
CHARP2P_NODE_LISTEN=/ip4/0.0.0.0/udp/4001/quic-v1
CHARP2P_NODE_IDENTITY=data/node-identity.key
```

To refuse abusive peers, list their peer IDs one per line in a text file and
pass it with `--blocked-peers <file>` or `CHARP2P_NODE_BLOCKED_PEERS`. Blank
lines and lines starting with `#` are ignored. The file is read once at
startup, is limited to 256 KiB and 4,096 peer IDs, and an invalid line stops
startup. Blocked peers cannot connect, route through the DHT, or reserve relay
circuits on this node; the block does not affect other nodes or any group.

On Unix, a new identity file is created with mode `0600`; startup fails when an
existing identity is accessible by group or other users. Back up this file if
the node should keep the same peer ID.

Open the selected UDP port in the host firewall. The process prints a
multiaddress ending in `/p2p/<peer-id>`. For local client development, assign
that complete address to `CHARP2P_BOOTSTRAP_NODES` before starting the app.
Multiple client bootstrap addresses are separated by semicolons.

The process logs only its peer ID, listen addresses, shutdown, and coarse DHT
operation failures. It does not log discovery keys or connected peer IDs.
Relay operators can still observe source and destination peer metadata, timing,
and traffic volume; relayed peer streams remain end-to-end authenticated and
encrypted.
