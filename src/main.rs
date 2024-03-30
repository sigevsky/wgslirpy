#![allow(unused_braces)]
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf, sync::Arc,
};

use argh::FromArgs;

/// Expose internet access without root using Wireguard
#[derive(FromArgs)]
pub struct Opts {
    /// main private key of this Wireguard node, base64-encoded
    #[argh(option, short = 'k')]
    pub private_key: Option<String>,

    /// main private key of this Wireguard node (content of a specified file), base64-encoded
    #[argh(option, short = 'f')]
    pub private_key_file: Option<PathBuf>,

    /// peer's public key
    #[argh(option, short = 'K')]
    pub peer_key: String,

    /// address of the peer's UDP socket, where to send keepalives
    #[argh(option, short = 'p')]
    pub peer_endpoint: Option<SocketAddr>,

    /// keepalive interval, in seconds
    #[argh(option, short = 'a')]
    pub keepalive_interval: Option<u16>,

    /// where to bind our own UDP socket for Wireguard connection
    #[argh(option, short = 'b')]
    pub bind_ip_port: SocketAddr,

    /// use this UDP socket address as a simple A/AAAA-only DNS server within Wireguard network
    #[argh(option, short = 'D')]
    pub dns: Option<SocketAddr>,

    /// reply to ICMP pings on this single address within Wireguard network
    #[argh(option, short = 'P')]
    pub pingable: Option<IpAddr>,

    /// maximum transfer unit to use for TCP. Default is 1420.
    #[argh(option, default = "1420")]
    pub mtu: usize,

    /// in-application socket TCP buffer size. Note that operating system socket buffer also applies.
    #[argh(option, default = "65535")]
    pub tcp_buffer_size: usize,

    /// nubmer of outgoing (to wireguard) packets to hold in a queue
    #[argh(option, default = "256")]
    pub transmit_queue_capacity: usize,

    /// forward this host UDP port into Wireguard network.
    /// You need to specify triplet of socket addresses: host, source (optional) and dest.
    /// Host address is address to bind operating system socket to.
    /// source and dest addreses are used within Wireguard network.
    /// Example: -u 0.0.0.0:1234,10.0.2.1:1234,10.0.2.15:1234
    #[argh(option, short = 'u', from_str_fn(parse_sa_pair))]
    pub incoming_udp: Vec<PortForward>,

    /// forward this host TCP port into Wireguard network.
    /// You need to specify triplet of socket addresses: host, source (optional) and dest.
    /// Host address is address to bind operating system socket to.
    /// source and dest addreses are used within Wireguard network.
    /// If source port is 0, roundrobin is used.
    /// Example: -t 0.0.0.0:1234,,10.0.2.15:1234
    #[argh(option, short = 't', from_str_fn(parse_sa_pair))]
    pub incoming_tcp: Vec<PortForward>,
}

fn parse_sa_pair(x: &str) -> Result<PortForward, String> {
    let chunks = x.split(',').collect::<Vec<_>>();
    if chunks.len() != 3 {
        return Err(
            "Argument to -u or -t must be comma-separated triplet of socket addresses".to_owned(),
        );
    }
    let Ok(sa1): Result<SocketAddr, _> = chunks[0].parse() else {
        return Err(format!("Failed to parse {} as a socket address", chunks[0]));
    };
    let sa2 = if chunks[1].is_empty() {
        None
    } else {
        let Ok(sa2): Result<SocketAddr, _> = chunks[1].parse() else {
            return Err(format!("Failed to parse {} as a socket address", chunks[1]));
        };
        Some(sa2)
    };
    let Ok(sa3): Result<SocketAddr, _> = chunks[2].parse() else {
        return Err(format!("Failed to parse {} as a socket address", chunks[2]));
    };
    Ok(PortForward {
        host: sa1,
        src: sa2,
        dst: sa3,
    })
}

use hyper::{
    service::{make_service_fn, service_fn},
    Body, Request, Response, Server,
};
use libwgslirpy::{parsebase64_32, router::{DefaultDnsNameLookup, DnsAddr, PortForward}};
use prometheus::{Encoder, TextEncoder};
use tokio::sync::mpsc;
use tracing::Level;
use tracing_log::LogTracer;
use tracing_subscriber::FmtSubscriber;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();

    LogTracer::init()?;

    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    let (state_reporter, mut state_listener) = mpsc::channel(40);

    let dns_addr: IpAddr = IpAddr::V4(Ipv4Addr::new(176, 16, 255, 2));

    let router_config = libwgslirpy::router::Opts {
        dns_addr: Some(DnsAddr {
            addr: SocketAddr::new(dns_addr, 53),
            name_lookup: Arc::new(DefaultDnsNameLookup{}),
        }),
        pingable: None,
        mtu: 1500,
        send_tcp_buffer_size: 65536 * 4,
        receive_tcp_buffer_size: 65536 * 4,
        incoming_udp: vec![],
        incoming_tcp: vec![],
        mb_bind_target: None,
    };

    // q
    let wg_config = libwgslirpy::wg::Opts {
        private_key: parsebase64_32("eJXgrJlu7oJJxIJeiHZlyEBZNr4bZ/qP9OgLbZ1MI3s=")
            .unwrap()
            .into(),
        peer_key: parsebase64_32("mK+EqWw5JpGsH6NdFp4nif7/O8CBbjLfE3WFqleyHRU=")
            .unwrap()
            .into(),
        peer_endpoint: Some("192.168.0.100:9003".parse().unwrap()),
        keepalive_interval: Some(25),
        bind_ip_port: "0.0.0.0:9097".parse().unwrap(),
        connection_state_reporter: Some(state_reporter),
    };

    tokio::spawn(async move {
        loop {
            if let Some(new_state) = state_listener.recv().await {
                tracing::info!("Wg state has updated with {:?}", new_state);
            }
        }
    });

    tokio::spawn(async {
        let make_svc =
            make_service_fn(|_conn| async { Ok::<_, hyper::Error>(service_fn(serve_req)) });

        let addr = SocketAddr::from(([0, 0, 0, 0], 5444));
        let server = Server::bind(&addr).serve(make_svc);

        println!("Listening on http://{}", addr);
        if let Err(e) = server.await {
            eprintln!("server error: {}", e);
        }
    });

    libwgslirpy::run(wg_config, router_config, 256).await?;

    Ok(())
}

async fn serve_req(_req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    let metric_families = prometheus::gather();
    let encoder = TextEncoder::new();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    let response = Response::builder()
        .status(200)
        .body(Body::from(buffer))
        .unwrap();
    Ok(response)
}
