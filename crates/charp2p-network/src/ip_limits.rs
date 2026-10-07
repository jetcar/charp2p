//! Bounds established inbound connections that share one remote IP address.

use std::{
    collections::HashMap,
    convert::Infallible,
    fmt,
    net::IpAddr,
    task::{Context, Poll},
};

use libp2p::{
    Multiaddr, PeerId,
    core::{ConnectedPoint, Endpoint, transport::PortUse},
    multiaddr::Protocol,
    swarm::{
        ConnectionClosed, ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler,
        THandlerInEvent, THandlerOutEvent, ToSwarm, behaviour::ConnectionEstablished, dummy,
    },
};

/// Refuses an established inbound connection when its remote IP address
/// already holds the configured number of inbound connections. Relayed
/// connections carry the relay's address, not the peer's, and are not counted.
pub(crate) struct Behaviour {
    max_per_ip: Option<u32>,
    inbound: HashMap<ConnectionId, IpAddr>,
    per_ip: HashMap<IpAddr, u32>,
}

impl Behaviour {
    pub(crate) fn new(max_per_ip: Option<u32>) -> Self {
        Self {
            max_per_ip,
            inbound: HashMap::new(),
            per_ip: HashMap::new(),
        }
    }

    fn release(&mut self, connection_id: ConnectionId) {
        let Some(ip) = self.inbound.remove(&connection_id) else {
            return;
        };
        if let Some(count) = self.per_ip.get_mut(&ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.per_ip.remove(&ip);
            }
        }
    }
}

/// Returns the direct remote IP address, or `None` for relayed or
/// non-IP addresses.
fn direct_ip(address: &Multiaddr) -> Option<IpAddr> {
    if address
        .iter()
        .any(|protocol| matches!(protocol, Protocol::P2pCircuit))
    {
        return None;
    }
    address.iter().find_map(|protocol| match protocol {
        Protocol::Ip4(ip) => Some(IpAddr::V4(ip)),
        Protocol::Ip6(ip) => Some(IpAddr::V6(ip)),
        _ => None,
    })
}

/// The per-IP inbound connection limit was reached.
#[derive(Debug)]
pub(crate) struct PerIpLimitExceeded {
    limit: u32,
}

impl fmt::Display for PerIpLimitExceeded {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "at most {} inbound connections per IP address are allowed",
            self.limit
        )
    }
}

impl std::error::Error for PerIpLimitExceeded {}

impl NetworkBehaviour for Behaviour {
    type ConnectionHandler = dummy::ConnectionHandler;
    type ToSwarm = Infallible;

    fn handle_established_inbound_connection(
        &mut self,
        _: ConnectionId,
        _: PeerId,
        _: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        if let (Some(limit), Some(ip)) = (self.max_per_ip, direct_ip(remote_addr))
            && self.per_ip.get(&ip).copied().unwrap_or(0) >= limit
        {
            return Err(ConnectionDenied::new(PerIpLimitExceeded { limit }));
        }
        Ok(dummy::ConnectionHandler)
    }

    fn handle_established_outbound_connection(
        &mut self,
        _: ConnectionId,
        _: PeerId,
        _: &Multiaddr,
        _: Endpoint,
        _: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(dummy::ConnectionHandler)
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        match event {
            FromSwarm::ConnectionEstablished(ConnectionEstablished {
                connection_id,
                endpoint: ConnectedPoint::Listener { send_back_addr, .. },
                ..
            }) => {
                if let Some(ip) = direct_ip(send_back_addr) {
                    self.inbound.insert(connection_id, ip);
                    *self.per_ip.entry(ip).or_default() += 1;
                }
            }
            FromSwarm::ConnectionClosed(ConnectionClosed { connection_id, .. }) => {
                self.release(connection_id);
            }
            _ => {}
        }
    }

    fn on_connection_handler_event(
        &mut self,
        _: PeerId,
        _: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        match event {}
    }

    fn poll(&mut self, _: &mut Context<'_>) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::direct_ip;

    #[test]
    fn direct_ip_reads_direct_addresses_and_skips_relayed_ones() {
        assert_eq!(
            direct_ip(&"/ip4/192.0.2.7/udp/4001/quic-v1".parse().unwrap()),
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)))
        );
        assert_eq!(
            direct_ip(&"/ip6/2001:db8::1/tcp/4001".parse().unwrap()),
            Some("2001:db8::1".parse().unwrap())
        );
        assert_eq!(
            direct_ip(
                &"/ip4/192.0.2.7/udp/4001/quic-v1/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN/p2p-circuit"
                    .parse()
                    .unwrap()
            ),
            None
        );
        assert_eq!(direct_ip(&"/dns4/example.org/tcp/1".parse().unwrap()), None);
    }
}
