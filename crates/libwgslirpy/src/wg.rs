//! Simplified interface to `boringtun` based on Tokio's mpsc channels.

use std::{net::SocketAddr, time::Duration};

use base64::Engine;
use boringtun::noise::{errors::WireGuardError, TunnResult};
pub use boringtun::x25519::{PublicKey, StaticSecret};
use bytes::BytesMut;
use prometheus::{Counter, Gauge};
use tokio::sync::mpsc::{Receiver, Sender};
use tracing::{error, warn};

use crate::TEAR_OF_ALLOCATION_SIZE;

lazy_static! {
    static ref WG_IN: Counter = register_counter!(opts!("wg_in", "bytes")).unwrap();
    static ref WG_OUT: Counter = register_counter!(opts!("wg_out", "bytes")).unwrap();
    static ref FROM_WG_USED: Gauge = register_gauge!(opts!("from_wg_used", "slots")).unwrap();
    static ref TEAR_OFF_BYTES: Gauge = register_gauge!(opts!("tear_of_used", "bytes")).unwrap();
}

/// Tracks current state of the wirguard connection
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum WgConnectionState {
    /// WireGuard has yet to establish connection with a peer
    Disconnected,
    /// Connection to a peer is pending
    Pending,
    /// Connection is established
    Connected,
    /// Seen errors while trying to read to a socket
    Malfunctioning,
}

/// Options for being a Wireguard peer
pub struct Opts {
    /// Private key of this Wireguard node.
    ///
    /// Use `parsebase64_32` and `into()` to specify it from a string.
    pub private_key: StaticSecret,

    /// Public key of single Wireguard peer we are connecting to.
    ///
    /// Use `parsebase64_32` and `into()` to specify it from a string.
    pub peer_key: PublicKey,

    /// Static socket address of Wireguard peer to connect to.
    ///
    /// If it is missing, it listens for incoming datagrams and remembers last seen `from` address
    /// (data from which Wireguard implementation recognized) for `sendto` purposes.
    pub peer_endpoint: Option<SocketAddr>,

    /// How often to send keepalive packets to the peer.
    pub keepalive_interval: Option<u16>,

    /// Socket address to bind local UDP port to.
    pub bind_ip_port: SocketAddr,

    /// Socket address to bind local UDP port to.
    pub connection_state_reporter: Option<Sender<WgConnectionState>>,
}

impl Opts {
    /// Start Wireguard implementation using this options set.
    ///
    /// Received IP packets would appear at `tx_fromwg`'s channel.
    /// IP packets to be sent to Wireguard tunnel is to be written to `rx_towg`'s channel.
    pub async fn start(
        mut self,
        tx_fromwg: Sender<BytesMut>,
        mut rx_towg: Receiver<BytesMut>,
    ) -> anyhow::Result<()> {
        let mut wg = boringtun::noise::Tunn::new(
            self.private_key.clone(),
            self.peer_key,
            None,
            self.keepalive_interval,
            0,
            None,
        )
        .map_err(|e| anyhow::anyhow!(e))?;

        let udp = tokio::net::UdpSocket::bind(self.bind_ip_port).await?;

        let mut current_peer_addr = self.peer_endpoint;
        let static_peer_addr = self.peer_endpoint;

        let mut each_second = tokio::time::interval(Duration::from_secs(1));
        let mut udp_recv_buf = [0; 8182 - 32];
        let mut wg_scratch_buf = [0; 8182];
        let mut tear_off_buffer = BytesMut::with_capacity(TEAR_OF_ALLOCATION_SIZE);
        let mut connection_state = ConnectionState {
            current: WgConnectionState::Disconnected,
            reporter: self.connection_state_reporter.take(),
        };

        loop {
            let mut last_seen_recv_address = None;

            let (mut tr, should_repeat) = if connection_state.current
                == WgConnectionState::Disconnected
                && current_peer_addr.is_some()
            {
                connection_state.update_state(WgConnectionState::Pending);
                (
                    wg.format_handshake_initiation(&mut wg_scratch_buf, false),
                    false,
                )
            } else {
                tokio::select! {
                    _instant = each_second.tick() => {
                        (wg.update_timers(&mut wg_scratch_buf), false)
                    }
                    ret = udp.recv_from(&mut udp_recv_buf[..]) => {
                        let ret = ret?;
                        WG_IN.inc_by(ret.0 as f64);
                        let buf : &[u8] = &udp_recv_buf[0..(ret.0)];
                        let from : SocketAddr = ret.1;

                        last_seen_recv_address = Some(from);
                        connection_state.update_state(WgConnectionState::Connected);
                        (wg.decapsulate(None, buf, &mut wg_scratch_buf), true)
                    }
                    ret = rx_towg.recv() => {
                        let Some(incoming) : Option<BytesMut> = ret else {
                            warn!("Finished possible packets into wg");
                            break
                        };
                        (wg.encapsulate(&incoming[..], &mut wg_scratch_buf), false)
                    }
                }
            };

            loop {
                if !matches!(tr, TunnResult::Err(..)) {
                    if last_seen_recv_address.is_some()
                        && current_peer_addr.is_none()
                        && static_peer_addr.is_none()
                    {
                        current_peer_addr = last_seen_recv_address;
                    }
                }

                match tr {
                    TunnResult::Done => (),
                    TunnResult::Err(WireGuardError::ConnectionExpired) => {
                        error!("Connection expired");
                        connection_state.update_state(WgConnectionState::Disconnected)
                    }
                    TunnResult::Err(e) => {
                        error!("boringturn error: {:?}", e);
                    }
                    TunnResult::WriteToNetwork(b) => {
                        if let Some(cpa) = current_peer_addr {
                            match udp.send_to(b, cpa).await {
                                Ok(_n) => {
                                    WG_OUT.inc_by(_n as f64);
                                    if connection_state.current == WgConnectionState::Malfunctioning
                                    {
                                        connection_state.update_state(WgConnectionState::Pending);
                                    } else if connection_state.current
                                        == WgConnectionState::Connected
                                        && wg.time_since_last_handshake().is_none()
                                    {
                                        connection_state.update_state(WgConnectionState::Pending);
                                    }
                                }
                                Err(e) => {
                                    connection_state
                                        .update_state(WgConnectionState::Malfunctioning);
                                    error!("Failed to send wiregaurd packet to peer: {e}")
                                }
                            }
                            if should_repeat {
                                tr = wg.decapsulate(None, b"", &mut wg_scratch_buf);
                                continue;
                            }
                        } else {
                            error!(
                                "Trying to send a wireguard packet without configured peer address"
                            );
                        }
                    }
                    TunnResult::WriteToTunnelV4(b, _) | TunnResult::WriteToTunnelV6(b, _) => {
                        FROM_WG_USED.set((tx_fromwg.max_capacity() - tx_fromwg.capacity()) as f64);

                        tear_off_buffer.extend_from_slice(b);
                        TEAR_OFF_BYTES.set(tear_off_buffer.len() as f64);

                        tx_fromwg.send(tear_off_buffer.split()).await?;

                        if tear_off_buffer.capacity() < 2048 {
                            tear_off_buffer = BytesMut::with_capacity(TEAR_OF_ALLOCATION_SIZE);
                        }
                    }
                }
                break;
            }
        }
        #[allow(unreachable_code)]
        Ok::<_, anyhow::Error>(())
    }
}

struct ConnectionState {
    current: WgConnectionState,
    reporter: Option<Sender<WgConnectionState>>,
}

impl ConnectionState {
    fn update_state(&mut self, new_state: WgConnectionState) {
        let has_updated = match (self.current, new_state) {
            (WgConnectionState::Disconnected, WgConnectionState::Pending)
            | (WgConnectionState::Pending, WgConnectionState::Malfunctioning)
            | (WgConnectionState::Pending, WgConnectionState::Connected)
            | (WgConnectionState::Pending, WgConnectionState::Disconnected)
            | (WgConnectionState::Connected, WgConnectionState::Malfunctioning)
            | (WgConnectionState::Connected, WgConnectionState::Pending)
            | (WgConnectionState::Connected, WgConnectionState::Disconnected)
            | (WgConnectionState::Malfunctioning, WgConnectionState::Pending)
            | (WgConnectionState::Malfunctioning, WgConnectionState::Disconnected) => true,
            _ => false,
        };

        if has_updated {
            if let Some(rp) = &self.reporter {
                let _ = rp.try_send(new_state);
            }

            self.current = new_state;
        }
    }
}

/// Helper funtion to simplify creating [`StaticSecret`]s and [`PublicKey`]s.
pub fn parsebase64_32(x: &str) -> anyhow::Result<[u8; 32]> {
    let b = base64::engine::general_purpose::STANDARD.decode(x)?;
    Ok(b[..].try_into()?)
}
