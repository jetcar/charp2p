# CharP2P routing node

`charp2p-node` is a standalone community bootstrap and Kademlia routing node.
It stores no group events or message payloads and rejects synchronization
requests. Relay service and production traffic controls are later increments.

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

On Unix, a new identity file is created with mode `0600`; startup fails when an
existing identity is accessible by group or other users. Back up this file if
the node should keep the same peer ID.

Open the selected UDP port in the host firewall. The process prints a
multiaddress ending in `/p2p/<peer-id>`. For local client development, assign
that complete address to `CHARP2P_BOOTSTRAP_NODES` before starting the app.
Multiple client bootstrap addresses are separated by semicolons.

The process logs only its peer ID, listen addresses, shutdown, and coarse DHT
operation failures. It does not log discovery keys or connected peer IDs.
