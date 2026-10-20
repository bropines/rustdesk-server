//! End-to-end checks of hbbs' TCP/WebSocket rendezvous hardening against the real binary:
//! RegisterPeer may only refresh an id its connection registered with RegisterPk, the
//! WebSocket port trusts forwarding headers only from a trusted proxy and gives every
//! connection its own address, RequestRelay gets the PunchHoleRequest checks and never
//! carries the controller's `control_permissions` to the peer, forwarding it over a
//! WebSocket registration is opt-in (`WS_PEERS`),
//! `WS_RELAY_SERVERS` gives WebSocket clients their own relays, and the opt-in
//! authorization hook (`AUTHZ_URL`) decides about attempts and sets the peer's
//! permissions.

use hbb_common::{
    bytes::Bytes,
    futures_util::{SinkExt, StreamExt},
    protobuf::{Message as _, MessageField},
    rendezvous_proto::*,
    sodiumoxide::crypto::{box_, secretbox, sign},
    tcp::FramedStream,
    tokio::{self, net::TcpStream},
    udp::FramedSocket,
    AddrMangle,
};
use std::{
    io::{Read, Write},
    net::{IpAddr, SocketAddr},
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio_tungstenite::{
    tungstenite::{client::IntoClientRequest, Message as WsMessage},
    WebSocketStream,
};

const B_ID: &str = "secpeerB1";
const B_IP: &str = "127.0.0.2";
const A_IP: &str = "127.0.0.1";
const X_IP: &str = "127.0.0.3";
const WAIT: u64 = 3000;

struct Hbbs {
    child: Child,
    port: u16,
    dir: tempfile::TempDir,
    pk: sign::PublicKey,
    licence: String,
}

impl Drop for Hbbs {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if std::thread::panicking() {
            if let Ok(log) = std::fs::read_to_string(self.dir.path().join("hbbs.log")) {
                eprintln!("---- hbbs log ----\n{log}");
            }
        }
    }
}

fn start_hbbs(port: u16, env: &[(&str, &str)]) -> Hbbs {
    let dir = tempfile::tempdir().unwrap();
    let log = std::fs::File::create(dir.path().join("hbbs.log")).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_hbbs"));
    cmd.current_dir(dir.path())
        .args(["-p", &port.to_string()])
        .env("TEST_HBBS", "no")
        .env("DB_URL", dir.path().join("db.sqlite3"))
        .env("RUST_LOG", "debug")
        .env_remove("WEBRTC")
        .env_remove("MUST_LOGIN")
        .env_remove("TCP_KEEPALIVE")
        .env_remove("ALWAYS_USE_RELAY")
        .env_remove("RUSTDESK_API_JWT_KEY")
        .env_remove("WS_PEERS")
        .env_remove("TRUSTED_PROXIES")
        .env_remove("WS_RELAY_SERVERS")
        .env_remove("AUTHZ_URL")
        .env_remove("AUTHZ_SECRET")
        .env_remove("AUTHZ_SECRET_FILE")
        .env_remove("AUTHZ_FAIL_CLOSED")
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log));
    for (k, v) in env {
        cmd.env(k, v);
    }
    let child = cmd.spawn().unwrap();
    let start = Instant::now();
    loop {
        if [port, port - 1, port + 2]
            .iter()
            .all(|p| std::net::TcpStream::connect(("127.0.0.1", *p)).is_ok())
        {
            break;
        }
        assert!(start.elapsed() < Duration::from_secs(30), "hbbs did not start");
        std::thread::sleep(Duration::from_millis(100));
    }
    let licence = std::fs::read_to_string(dir.path().join("id_ed25519.pub"))
        .unwrap()
        .trim()
        .to_owned();
    let raw = base64::decode(&licence).unwrap();
    let pk = sign::PublicKey::from_slice(&raw).unwrap();
    Hbbs {
        child,
        port,
        dir,
        pk,
        licence,
    }
}

/// Distinct port blocks per test so the tests can run in parallel.
fn port_for(slot: u16) -> u16 {
    // below the Linux ephemeral range (32768+), so client sockets cannot take them
    20000 + (std::process::id() % 200) as u16 * 50 + slot * 5
}

fn admin(h: &Hbbs, cmd: &str) -> String {
    let mut s = std::net::TcpStream::connect(("127.0.0.1", h.port - 1)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.write_all(cmd.as_bytes()).unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    out
}

fn server(h: &Hbbs) -> SocketAddr {
    format!("127.0.0.1:{}", h.port).parse().unwrap()
}

/// TCP rendezvous connection with the hbbs key exchange done.
async fn tcp_secure(h: &Hbbs, local_ip: &str) -> FramedStream {
    let local: SocketAddr = format!("{local_ip}:0").parse().unwrap();
    let mut s = FramedStream::new(server(h), Some(local), WAIT).await.unwrap();
    let bytes = s.next_timeout(WAIT).await.unwrap().unwrap();
    let msg = RendezvousMessage::parse_from_bytes(&bytes).unwrap();
    let Some(rendezvous_message::Union::KeyExchange(ex)) = msg.union else {
        panic!("expected KeyExchange, got {msg:?}");
    };
    let their_pk = sign::verify(&ex.keys[0], &h.pk).unwrap();
    let their_pk = box_::PublicKey::from_slice(&their_pk).unwrap();
    let (our_pk, our_sk) = box_::gen_keypair();
    let key = secretbox::gen_key();
    let nonce = box_::Nonce([0u8; box_::NONCEBYTES]);
    let sealed = box_::seal(&key.0, &nonce, &their_pk, &our_sk);
    let mut out = RendezvousMessage::new();
    out.set_key_exchange(KeyExchange {
        keys: vec![Bytes::from(our_pk.0.to_vec()), Bytes::from(sealed)],
        ..Default::default()
    });
    s.send(&out).await.unwrap();
    s.set_key(key);
    s
}

async fn tcp_recv(s: &mut FramedStream, ms: u64) -> Option<RendezvousMessage> {
    let deadline = Instant::now() + Duration::from_millis(ms);
    loop {
        let left = deadline.saturating_duration_since(Instant::now()).as_millis() as u64;
        if left == 0 {
            return None;
        }
        match s.next_timeout(left).await {
            Some(Ok(bytes)) if bytes.is_empty() => continue,
            Some(Ok(bytes)) => return Some(RendezvousMessage::parse_from_bytes(&bytes).unwrap()),
            _ => return None,
        }
    }
}

type Ws = WebSocketStream<TcpStream>;

/// WebSocket connection from `local_ip` to `server_ip`, with optional forwarding headers.
async fn ws_connect_from(h: &Hbbs, local_ip: &str, server_ip: IpAddr, headers: &[(&str, &str)]) -> Ws {
    let sock = if server_ip.is_ipv4() {
        tokio::net::TcpSocket::new_v4().unwrap()
    } else {
        tokio::net::TcpSocket::new_v6().unwrap()
    };
    sock.bind(format!("{local_ip}:0").parse().unwrap()).unwrap();
    let stream = sock
        .connect(SocketAddr::new(server_ip, h.port + 2))
        .await
        .unwrap();
    let mut req = format!("ws://127.0.0.1:{}", h.port + 2)
        .into_client_request()
        .unwrap();
    for (k, v) in headers {
        req.headers_mut().insert(
            tokio_tungstenite::tungstenite::http::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
            v.parse().unwrap(),
        );
    }
    tokio_tungstenite::client_async(req, stream).await.unwrap().0
}

async fn ws_connect(h: &Hbbs, local_ip: &str) -> Ws {
    ws_connect_from(h, local_ip, "127.0.0.1".parse().unwrap(), &[]).await
}

async fn ws_send(ws: &mut Ws, msg: &RendezvousMessage) {
    ws.send(WsMessage::Binary(msg.write_to_bytes().unwrap()))
        .await
        .unwrap();
}

/// Next binary frame, empty (keepalive) ones included.
async fn ws_next_frame(ws: &mut Ws, ms: u64) -> Option<Vec<u8>> {
    let deadline = Instant::now() + Duration::from_millis(ms);
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return None;
        }
        match tokio::time::timeout(left, ws.next()).await {
            Ok(Some(Ok(WsMessage::Binary(b)))) => return Some(b),
            Ok(Some(Ok(_))) => continue,
            _ => return None,
        }
    }
}

async fn ws_recv(ws: &mut Ws, ms: u64) -> Option<RendezvousMessage> {
    let deadline = Instant::now() + Duration::from_millis(ms);
    loop {
        let left = deadline.saturating_duration_since(Instant::now()).as_millis() as u64;
        match ws_next_frame(ws, left).await {
            Some(b) if b.is_empty() => continue,
            Some(b) => return Some(RendezvousMessage::parse_from_bytes(&b).unwrap()),
            None => return None,
        }
    }
}

async fn udp_recv(s: &mut FramedSocket, ms: u64) -> Option<RendezvousMessage> {
    match s.next_timeout(ms).await {
        Some(Ok((bytes, _))) => Some(RendezvousMessage::parse_from_bytes(&bytes).unwrap()),
        _ => None,
    }
}

fn register_pk_msg(id: &str) -> RendezvousMessage {
    let mut msg = RendezvousMessage::new();
    msg.set_register_pk(RegisterPk {
        id: id.to_owned(),
        uuid: Bytes::from(format!("uuid-of-{id}").into_bytes()),
        pk: Bytes::from(vec![7u8; 32]),
        ..Default::default()
    });
    msg
}

fn register_peer_msg(id: &str) -> RendezvousMessage {
    let mut msg = RendezvousMessage::new();
    msg.set_register_peer(RegisterPeer {
        id: id.to_owned(),
        ..Default::default()
    });
    msg
}

fn expect_register_peer_response(msg: Option<RendezvousMessage>) -> bool {
    match msg.and_then(|m| m.union) {
        Some(rendezvous_message::Union::RegisterPeerResponse(r)) => r.request_pk,
        other => panic!("expected RegisterPeerResponse, got {other:?}"),
    }
}

/// Registers B over UDP and returns its socket.
async fn register_udp_peer(h: &Hbbs) -> FramedSocket {
    let mut s = FramedSocket::new(format!("{B_IP}:0")).await.unwrap();
    s.send(&register_pk_msg(B_ID), server(h)).await.unwrap();
    let Some(rendezvous_message::Union::RegisterPkResponse(r)) =
        udp_recv(&mut s, WAIT).await.and_then(|m| m.union)
    else {
        panic!("no RegisterPkResponse");
    };
    assert_eq!(r.result.enum_value(), Ok(register_pk_response::Result::OK));
    s.send(&register_peer_msg(B_ID), server(h)).await.unwrap();
    assert!(
        !expect_register_peer_response(udp_recv(&mut s, WAIT).await),
        "B's own UDP RegisterPeer was refused"
    );
    s
}

/// Registers `id` over WebSocket and returns the connection.
async fn register_ws_peer(h: &Hbbs, id: &str) -> Ws {
    let mut ws = ws_connect(h, B_IP).await;
    ws_send(&mut ws, &register_pk_msg(id)).await;
    let Some(rendezvous_message::Union::RegisterPkResponse(r)) =
        ws_recv(&mut ws, WAIT).await.and_then(|m| m.union)
    else {
        panic!("no RegisterPkResponse over ws");
    };
    assert_eq!(r.result.enum_value(), Ok(register_pk_response::Result::OK));
    ws
}

fn punch_request(h: &Hbbs, token: &str) -> RendezvousMessage {
    let mut msg = RendezvousMessage::new();
    msg.set_punch_hole_request(PunchHoleRequest {
        id: B_ID.to_owned(),
        licence_key: h.licence.clone(),
        version: "1.4.2".to_owned(),
        token: token.to_owned(),
        ..Default::default()
    });
    msg
}

fn relay_request(id: &str, licence: &str, token: &str) -> RendezvousMessage {
    relay_request_via(id, licence, token, "relay.example.com:21117")
}

fn relay_request_via(id: &str, licence: &str, token: &str, relay: &str) -> RendezvousMessage {
    let mut msg = RendezvousMessage::new();
    msg.set_request_relay(RequestRelay {
        id: id.to_owned(),
        uuid: "9b2f1c3e-0000-4000-8000-000000000001".to_owned(),
        relay_server: relay.to_owned(),
        licence_key: licence.to_owned(),
        token: token.to_owned(),
        secure: true,
        ..Default::default()
    });
    msg
}

fn expect_refused(msg: Option<RendezvousMessage>, reason: &str) {
    match msg.and_then(|m| m.union) {
        Some(rendezvous_message::Union::RelayResponse(r)) => assert_eq!(r.refuse_reason, reason),
        other => panic!("expected a refused RelayResponse ({reason}), got {other:?}"),
    }
}

fn forwarded_relay(msg: Option<RendezvousMessage>) -> RequestRelay {
    match msg.and_then(|m| m.union) {
        Some(rendezvous_message::Union::RequestRelay(rr)) => {
            assert_eq!(rr.id, B_ID);
            assert!(rr.token.is_empty(), "the controller's token was forwarded");
            assert!(rr.licence_key.is_empty(), "the licence key was forwarded");
            assert!(!rr.socket_addr.is_empty());
            rr
        }
        other => panic!("expected a forwarded RequestRelay, got {other:?}"),
    }
}

fn expect_forwarded_relay(msg: Option<RendezvousMessage>) -> RequestRelay {
    let rr = forwarded_relay(msg);
    assert_eq!(rr.relay_server, "relay.example.com:21117");
    rr
}

fn punch_hole(msg: Option<RendezvousMessage>) -> PunchHole {
    match msg.and_then(|m| m.union) {
        Some(rendezvous_message::Union::PunchHole(ph)) => ph,
        other => panic!("expected PunchHole, got {other:?}"),
    }
}

fn punch_hole_addr(msg: Option<RendezvousMessage>) -> SocketAddr {
    AddrMangle::decode(&punch_hole(msg).socket_addr)
}

// RegisterPeer has no uuid: over TCP/WebSocket it must not move a peer that another
// connection registered (upstream ignores it there; hbbs used to accept it whenever the
// IP was unchanged or loopback).
#[tokio::test]
async fn register_peer_cannot_take_over_another_peer() {
    let h = start_hbbs(port_for(0), &[]);
    let mut b = register_udp_peer(&h).await;

    let mut x_tcp = tcp_secure(&h, X_IP).await;
    x_tcp.send(&register_peer_msg(B_ID)).await.unwrap();
    assert!(expect_register_peer_response(tcp_recv(&mut x_tcp, WAIT).await));
    let mut x_ws = ws_connect(&h, X_IP).await;
    ws_send(&mut x_ws, &register_peer_msg(B_ID)).await;
    assert!(expect_register_peer_response(ws_recv(&mut x_ws, WAIT).await));

    // B's address did not move: a punch request still reaches its UDP socket
    let mut a = tcp_secure(&h, A_IP).await;
    a.send(&punch_request(&h, "")).await.unwrap();
    punch_hole_addr(udp_recv(&mut b, WAIT).await);

    // a connection may refresh the id it registered itself
    let mut c = register_ws_peer(&h, "secpeerC1").await;
    ws_send(&mut c, &register_peer_msg("secpeerC1")).await;
    assert!(!expect_register_peer_response(ws_recv(&mut c, WAIT).await));
    // but not another one
    ws_send(&mut c, &register_peer_msg(B_ID)).await;
    assert!(expect_register_peer_response(ws_recv(&mut c, WAIT).await));
}

// Behind one IP (one reverse proxy), two browser clients used to share `ip:0`, so the
// answer for one could go to the other.
#[tokio::test]
async fn ws_clients_behind_one_proxy_get_their_own_address() {
    let h = start_hbbs(port_for(1), &[]);
    let mut b = register_udp_peer(&h).await;
    let via_proxy = [("X-Real-IP", "203.0.113.5")];
    let lo: IpAddr = "127.0.0.1".parse().unwrap();
    let mut a1 = ws_connect_from(&h, A_IP, lo, &via_proxy).await;
    let mut a2 = ws_connect_from(&h, A_IP, lo, &via_proxy).await;

    ws_send(&mut a1, &punch_request(&h, "")).await;
    let addr1 = punch_hole_addr(udp_recv(&mut b, WAIT).await);
    ws_send(&mut a2, &punch_request(&h, "")).await;
    let addr2 = punch_hole_addr(udp_recv(&mut b, WAIT).await);
    // the proxy (loopback) is trusted: the header's IP, the proxy connection's port
    assert_eq!(addr1.ip(), "203.0.113.5".parse::<IpAddr>().unwrap());
    assert_eq!(addr2.ip(), addr1.ip());
    assert_ne!(addr1.port(), 0);
    assert_ne!(addr1.port(), addr2.port());

    // B answers the second one; only that one gets it
    let mut b_ans = tcp_secure(&h, B_IP).await;
    let mut msg = RendezvousMessage::new();
    msg.set_punch_hole_sent(PunchHoleSent {
        socket_addr: AddrMangle::encode(addr2).into(),
        id: B_ID.to_owned(),
        version: "1.4.2".to_owned(),
        ..Default::default()
    });
    b_ans.send(&msg).await.unwrap();
    match ws_recv(&mut a2, WAIT).await.and_then(|m| m.union) {
        Some(rendezvous_message::Union::PunchHoleResponse(_)) => {}
        other => panic!("a2 got no PunchHoleResponse: {other:?}"),
    }
    assert!(ws_recv(&mut a1, 500).await.is_none(), "a1 got a2's answer");

    // a client that is not a trusted proxy cannot pick its address
    let Some(own) = local_ip_address::local_ip().ok().filter(|ip| !ip.is_loopback()) else {
        eprintln!("no non-loopback address, skipping the untrusted-peer check");
        return;
    };
    let mut direct =
        ws_connect_from(&h, &own.to_string(), own, &[("X-Real-IP", "198.51.100.7")]).await;
    ws_send(&mut direct, &punch_request(&h, "")).await;
    assert_eq!(punch_hole_addr(udp_recv(&mut b, WAIT).await).ip(), own);
}

// RequestRelay gets the PunchHoleRequest checks (MUST_LOGIN, licence key, size) and the
// forwarded request carries neither the controller's token, the key nor permissions.
#[tokio::test]
async fn request_relay_is_checked_like_punch_hole_request() {
    let h = start_hbbs(port_for(2), &[("MUST_LOGIN", "Y")]);
    let mut b = register_udp_peer(&h).await;

    // MUST_LOGIN: no token, refused and not forwarded
    let mut a = tcp_secure(&h, A_IP).await;
    a.send(&relay_request(B_ID, &h.licence, "")).await.unwrap();
    expect_refused(tcp_recv(&mut a, WAIT).await, "Connection failed, please login!");
    assert!(udp_recv(&mut b, 500).await.is_none());

    // with the key and a token (no JWT key configured: any token passes)
    let mut a = tcp_secure(&h, A_IP).await;
    let a_addr = a.local_addr();
    a.send(&relay_request(B_ID, &h.licence, "token")).await.unwrap();
    let rr = expect_forwarded_relay(udp_recv(&mut b, WAIT).await);
    assert_eq!(
        hbb_common::try_into_v4(AddrMangle::decode(&rr.socket_addr)),
        a_addr
    );

    // control_permissions/controlled_context are the rendezvous server's to set (RustDesk
    // clients apply them over the owner's settings): the controller's never reach B
    let mut a = tcp_secure(&h, A_IP).await;
    let mut msg = relay_request(B_ID, &h.licence, "token");
    if let Some(rendezvous_message::Union::RequestRelay(rr)) = msg.union.as_mut() {
        rr.control_permissions = MessageField::some(ControlPermissions {
            permissions: u64::MAX,
            ..Default::default()
        });
        rr.controlled_context = MessageField::some(ControlledContext {
            conn_audit_ref: "forged".to_owned(),
            ..Default::default()
        });
    }
    a.send(&msg).await.unwrap();
    let rr = expect_forwarded_relay(udp_recv(&mut b, WAIT).await);
    assert!(rr.control_permissions.is_none(), "the controller's permissions were forwarded");
    assert!(rr.controlled_context.is_none(), "the controller's context was forwarded");

    // a wrong key is refused
    let mut x = tcp_secure(&h, X_IP).await;
    x.send(&relay_request(B_ID, "wrong", "token")).await.unwrap();
    expect_refused(tcp_recv(&mut x, WAIT).await, "Key mismatch");
    // no key, and no punch request from this IP: refused
    let mut x = tcp_secure(&h, X_IP).await;
    x.send(&relay_request(B_ID, "", "token")).await.unwrap();
    expect_refused(tcp_recv(&mut x, WAIT).await, "Key mismatch");
    assert!(udp_recv(&mut b, 500).await.is_none());

    // RustDesk clients: PunchHoleRequest with the key, then RequestRelay without it
    let mut a = tcp_secure(&h, A_IP).await;
    a.send(&punch_request(&h, "token")).await.unwrap();
    punch_hole_addr(udp_recv(&mut b, WAIT).await);
    let mut a = tcp_secure(&h, A_IP).await;
    a.send(&relay_request(B_ID, "", "token")).await.unwrap();
    expect_forwarded_relay(udp_recv(&mut b, WAIT).await);

    // oversized fields
    let mut a = tcp_secure(&h, A_IP).await;
    let mut msg = relay_request(B_ID, &h.licence, "token");
    if let Some(rendezvous_message::Union::RequestRelay(rr)) = msg.union.as_mut() {
        rr.uuid = "x".repeat(65);
    }
    a.send(&msg).await.unwrap();
    expect_refused(tcp_recv(&mut a, WAIT).await, "Invalid relay request");

    // unknown peer: nothing to forward to (not loaded from the database either)
    let mut a = tcp_secure(&h, A_IP).await;
    a.send(&relay_request("nosuchpeer", &h.licence, "token"))
        .await
        .unwrap();
    assert!(udp_recv(&mut b, 500).await.is_none());
}

// Forwarding RequestRelay over the peer's WebSocket registration is opt-in (WS_PEERS);
// by default it goes over UDP, as upstream.
#[tokio::test]
async fn request_relay_over_websocket_only_with_ws_peers() {
    let h = start_hbbs(port_for(3), &[]);
    let mut b = register_ws_peer(&h, B_ID).await;
    assert!(admin(&h, "wp").contains("WS_PEERS: false"));
    assert!(admin(&h, "h").contains("ws-peers(wp) [Y|N]"));

    let mut a = tcp_secure(&h, A_IP).await;
    a.send(&relay_request(B_ID, &h.licence, "token")).await.unwrap();
    assert!(ws_recv(&mut b, 1000).await.is_none());

    admin(&h, "ws-peers Y");
    assert!(admin(&h, "wp").contains("WS_PEERS: true"));
    let mut a = tcp_secure(&h, A_IP).await;
    a.send(&relay_request(B_ID, &h.licence, "token")).await.unwrap();
    expect_forwarded_relay(ws_recv(&mut b, WAIT).await);
    // the registration is not consumed
    let mut a = tcp_secure(&h, A_IP).await;
    a.send(&relay_request(B_ID, &h.licence, "token")).await.unwrap();
    expect_forwarded_relay(ws_recv(&mut b, WAIT).await);

    // once B's connection is gone, nothing is sent to its old registration
    drop(b);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut b2 = register_ws_peer(&h, B_ID).await;
    let mut a = tcp_secure(&h, A_IP).await;
    a.send(&relay_request(B_ID, &h.licence, "token")).await.unwrap();
    expect_forwarded_relay(ws_recv(&mut b2, WAIT).await);
}

// With TCP_KEEPALIVE only a connection with an accepted RegisterPk gets keepalives (and
// keeps its id online); naming an id in RegisterPeer is not enough.
#[tokio::test]
async fn keepalive_only_after_an_accepted_register_pk() {
    let h = start_hbbs(port_for(4), &[("TCP_KEEPALIVE", "Y")]);
    let mut registered = register_ws_peer(&h, "secpeerK1").await;
    let mut named = ws_connect(&h, X_IP).await;
    ws_send(&mut named, &register_peer_msg("secpeerK1")).await;
    assert!(expect_register_peer_response(ws_recv(&mut named, WAIT).await));

    // the keepalive interval is 12 s
    let (got, other) = tokio::join!(
        ws_next_frame(&mut registered, 14_000),
        ws_next_frame(&mut named, 14_000)
    );
    assert_eq!(got, Some(Vec::new()), "no keepalive for the registered connection");
    assert_eq!(other, None, "keepalive for a connection that only named an id");
}

// WS_RELAY_SERVERS (opt-in): WebSocket (browser) controllers get a relay from that list,
// for punch requests and for the peer side of their RequestRelay; everyone else gets the
// normal relay choice.
#[tokio::test]
async fn ws_relay_servers_only_for_websocket_clients() {
    let ws_list = ["127.0.0.9:21117", "127.0.0.10:21117"];
    let h = start_hbbs(
        port_for(5),
        &[
            ("RELAY_SERVERS", "127.0.0.5:21117"),
            ("WS_RELAY_SERVERS", "127.0.0.9:21117,127.0.0.10:21117"),
        ],
    );
    let mut b = register_udp_peer(&h).await;

    // a TCP controller: the relay servers
    let mut a = tcp_secure(&h, A_IP).await;
    a.send(&punch_request(&h, "")).await.unwrap();
    assert_eq!(punch_hole(udp_recv(&mut b, WAIT).await).relay_server, "127.0.0.5:21117");
    // a WebSocket controller: WS_RELAY_SERVERS, in rotation
    let mut seen = Vec::new();
    for _ in 0..2 {
        let mut w = ws_connect(&h, A_IP).await;
        ws_send(&mut w, &punch_request(&h, "")).await;
        let rs = punch_hole(udp_recv(&mut b, WAIT).await).relay_server;
        assert!(ws_list.contains(&rs.as_str()), "{rs}");
        seen.push(rs);
    }
    assert_ne!(seen[0], seen[1]);

    // RequestRelay from a WebSocket controller: a relay outside the list is replaced,
    // one in it is kept
    let mut w = ws_connect(&h, A_IP).await;
    ws_send(&mut w, &relay_request(B_ID, &h.licence, "")).await;
    let rs = forwarded_relay(udp_recv(&mut b, WAIT).await).relay_server;
    assert!(ws_list.contains(&rs.as_str()), "{rs}");
    let mut w = ws_connect(&h, A_IP).await;
    ws_send(&mut w, &relay_request_via(B_ID, &h.licence, "", "127.0.0.10:21117")).await;
    assert_eq!(
        forwarded_relay(udp_recv(&mut b, WAIT).await).relay_server,
        "127.0.0.10:21117"
    );
    // from TCP: forwarded as requested, as upstream
    let mut a = tcp_secure(&h, A_IP).await;
    a.send(&relay_request(B_ID, &h.licence, "")).await.unwrap();
    expect_forwarded_relay(udp_recv(&mut b, WAIT).await);
}

/// A call the authorization stub received.
#[derive(Clone, Debug)]
struct AuthzCall {
    request_line: String,
    authorization: Option<String>,
    content_type: Option<String>,
    body: serde_json::Value,
}

/// An HTTP server standing in for the AUTHZ_URL service. `reply` gets the request body
/// and returns the status and body to answer with, or None to never answer.
struct AuthzStub {
    url: String,
    calls: Arc<Mutex<Vec<AuthzCall>>>,
}

impl AuthzStub {
    fn calls(&self) -> Vec<AuthzCall> {
        self.calls.lock().unwrap().clone()
    }
}

fn authz_stub(reply: fn(&serde_json::Value) -> Option<(u16, String)>) -> AuthzStub {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!(
        "http://{}/internal/hbbs/authorize",
        listener.local_addr().unwrap()
    );
    let calls = Arc::new(Mutex::new(Vec::new()));
    let seen = calls.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let seen = seen.clone();
            std::thread::spawn(move || serve_authz_call(stream, reply, seen));
        }
    });
    AuthzStub { url, calls }
}

fn serve_authz_call(
    mut s: std::net::TcpStream,
    reply: fn(&serde_json::Value) -> Option<(u16, String)>,
    seen: Arc<Mutex<Vec<AuthzCall>>>,
) {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        match s.read(&mut tmp) {
            Ok(n) if n > 0 => buf.extend_from_slice(&tmp[..n]),
            _ => return,
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let header = |name: &str| {
        head.split("\r\n").skip(1).find_map(|line| {
            let (k, v) = line.split_once(':')?;
            k.trim()
                .eq_ignore_ascii_case(name)
                .then(|| v.trim().to_owned())
        })
    };
    let len: usize = header("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    while buf.len() < head_end + len {
        match s.read(&mut tmp) {
            Ok(n) if n > 0 => buf.extend_from_slice(&tmp[..n]),
            _ => return,
        }
    }
    let body = serde_json::from_slice(&buf[head_end..head_end + len]).unwrap_or_default();
    let answer = reply(&body);
    seen.lock().unwrap().push(AuthzCall {
        request_line: head.split("\r\n").next().unwrap_or_default().to_owned(),
        authorization: header("authorization"),
        content_type: header("content-type"),
        body,
    });
    match answer {
        Some((status, text)) => {
            let _ = write!(
                s,
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
                text.len()
            );
        }
        // never answers in time (hbbs gives up after 2 s)
        None => std::thread::sleep(Duration::from_secs(5)),
    }
}

/// Waits until hbbs has logged a line containing every one of `parts`; returns the log.
async fn wait_log(h: &Hbbs, parts: &[&str]) -> String {
    let start = Instant::now();
    loop {
        let log = std::fs::read_to_string(h.dir.path().join("hbbs.log")).unwrap_or_default();
        if log.lines().any(|l| parts.iter().all(|p| l.contains(p))) {
            return log;
        }
        assert!(
            start.elapsed() < Duration::from_millis(WAIT),
            "hbbs never logged a line with {parts:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Keyboard enabled (Permission 0, value 2), file transfer disabled (Permission 3,
/// value 1): RustDesk's 2 bits per permission.
const PERMS: u64 = 2 | (1 << (2 * 3));

fn authz_reply(body: &serde_json::Value) -> Option<(u16, String)> {
    let reply = match body["token"].as_str().unwrap_or_default() {
        "tok-allow" => format!(r#"{{"allow":true,"permissions":"{PERMS}"}}"#),
        "tok-plain" => r#"{"allow":true,"permissions":"0"}"#.to_owned(),
        "tok-deny" => r#"{"allow":false,"reason":"Not your device"}"#.to_owned(),
        "" => r#"{"allow":false}"#.to_owned(),
        "tok-500" => return Some((500, "{}".to_owned())),
        "tok-bad" => "not json".to_owned(),
        "tok-hang" => return None,
        other => panic!("unexpected token {other}"),
    };
    Some((200, reply))
}

fn punch_request_from(h: &Hbbs, token: &str, conn_type: ConnType) -> RendezvousMessage {
    let mut msg = punch_request(h, token);
    if let Some(rendezvous_message::Union::PunchHoleRequest(ph)) = msg.union.as_mut() {
        ph.conn_type = conn_type.into();
    }
    msg
}

fn permissions_of(field: &MessageField<ControlPermissions>) -> Option<u64> {
    field.as_ref().map(|p| p.permissions)
}

fn expect_punch_failure(msg: Option<RendezvousMessage>, reason: &str) {
    match msg.and_then(|m| m.union) {
        Some(rendezvous_message::Union::PunchHoleResponse(r)) => {
            assert_eq!(r.other_failure, reason)
        }
        other => panic!("expected a PunchHoleResponse ({reason}), got {other:?}"),
    }
}

// AUTHZ_URL (opt-in): each attempt is asked about (bearer secret, JSON body); an allowed
// one carries the service's permissions to the peer, in PunchHole, FetchLocalAddr and
// RequestRelay (never the controller's own); decisions are cached.
#[tokio::test]
async fn authz_allow_sets_the_peer_permissions() {
    let stub = authz_stub(authz_reply);
    let dir = tempfile::tempdir().unwrap();
    let secret_file = dir.path().join("authz.secret");
    std::fs::write(&secret_file, "  s3cret\n").unwrap();
    let h = start_hbbs(
        port_for(6),
        &[
            ("AUTHZ_URL", &stub.url),
            // the file wins
            ("AUTHZ_SECRET", "not-this-one"),
            ("AUTHZ_SECRET_FILE", secret_file.to_str().unwrap()),
        ],
    );
    let mut b = register_udp_peer(&h).await;

    let mut a = tcp_secure(&h, A_IP).await;
    a.send(&punch_request(&h, "tok-allow")).await.unwrap();
    let ph = punch_hole(udp_recv(&mut b, WAIT).await);
    assert_eq!(permissions_of(&ph.control_permissions), Some(PERMS));
    let calls = stub.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].request_line, "POST /internal/hbbs/authorize HTTP/1.1");
    assert_eq!(calls[0].authorization.as_deref(), Some("Bearer s3cret"));
    assert_eq!(calls[0].content_type.as_deref(), Some("application/json"));
    assert_eq!(
        calls[0].body,
        serde_json::json!({
            "target_id": B_ID,
            "token": "tok-allow",
            "conn_type": 0,
            "controller_ip": A_IP,
            "kind": "punch_hole",
        })
    );

    // the RequestRelay that follows uses the cached decision; the peer gets the
    // service's permissions, not the ones the controller sent
    let mut a = tcp_secure(&h, A_IP).await;
    let mut msg = relay_request(B_ID, &h.licence, "tok-allow");
    if let Some(rendezvous_message::Union::RequestRelay(rr)) = msg.union.as_mut() {
        rr.control_permissions = MessageField::some(ControlPermissions {
            permissions: u64::MAX,
            ..Default::default()
        });
    }
    a.send(&msg).await.unwrap();
    let rr = expect_forwarded_relay(udp_recv(&mut b, WAIT).await);
    assert_eq!(permissions_of(&rr.control_permissions), Some(PERMS));
    assert_eq!(stub.calls().len(), 1, "the decision was not cached");

    // another conn_type is another decision
    let mut a = tcp_secure(&h, A_IP).await;
    a.send(&punch_request_from(&h, "tok-allow", ConnType::FILE_TRANSFER))
        .await
        .unwrap();
    let ph = punch_hole(udp_recv(&mut b, WAIT).await);
    assert_eq!(permissions_of(&ph.control_permissions), Some(PERMS));
    let calls = stub.calls();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[1].body["conn_type"], 1);

    // behind the peer's IP: FetchLocalAddr, with the permissions too
    let mut same_ip = tcp_secure(&h, B_IP).await;
    same_ip.send(&punch_request(&h, "tok-allow")).await.unwrap();
    match udp_recv(&mut b, WAIT).await.and_then(|m| m.union) {
        Some(rendezvous_message::Union::FetchLocalAddr(fla)) => {
            assert_eq!(permissions_of(&fla.control_permissions), Some(PERMS))
        }
        other => panic!("expected FetchLocalAddr, got {other:?}"),
    }
    let calls = stub.calls();
    assert_eq!(calls.len(), 3);
    assert_eq!(calls[2].body["controller_ip"], B_IP);

    // allowed with permissions "0": the field stays unset
    let mut a = tcp_secure(&h, A_IP).await;
    a.send(&relay_request(B_ID, &h.licence, "tok-plain")).await.unwrap();
    let rr = expect_forwarded_relay(udp_recv(&mut b, WAIT).await);
    assert_eq!(rr.control_permissions, MessageField::none());
    let calls = stub.calls();
    assert_eq!(calls.len(), 4);
    assert_eq!(calls[3].body["kind"], "request_relay");
    // decisions are logged (at debug), the secret and tokens never are
    let log = wait_log(&h, &["AUTHZ: request_relay from 127.0.0.1 to", "allowed (service)"]).await;
    assert!(log.contains("AUTHZ_URL=http://127.0.0.1:"), "{log}");
    for secret in ["s3cret", "not-this-one", "tok-allow", "tok-plain"] {
        assert!(!log.contains(secret), "hbbs logged {secret}");
    }
}

// A refusal reaches the controller as the other checks' do, and nothing reaches the peer.
#[tokio::test]
async fn authz_deny_refuses_and_forwards_nothing() {
    let stub = authz_stub(authz_reply);
    let h = start_hbbs(
        port_for(7),
        &[("AUTHZ_URL", &stub.url), ("AUTHZ_SECRET", "s3cret")],
    );
    let mut b = register_udp_peer(&h).await;

    let mut a = tcp_secure(&h, A_IP).await;
    a.send(&punch_request(&h, "tok-deny")).await.unwrap();
    expect_punch_failure(tcp_recv(&mut a, WAIT).await, "Not your device");
    let mut a = tcp_secure(&h, A_IP).await;
    a.send(&relay_request(B_ID, &h.licence, "tok-deny")).await.unwrap();
    expect_refused(tcp_recv(&mut a, WAIT).await, "Not your device");
    // without a reason: the default one
    let mut a = tcp_secure(&h, A_IP).await;
    a.send(&punch_request(&h, "")).await.unwrap();
    expect_punch_failure(tcp_recv(&mut a, WAIT).await, "Access denied by the server policy");
    let mut w = ws_connect(&h, A_IP).await;
    ws_send(&mut w, &relay_request(B_ID, &h.licence, "")).await;
    expect_refused(ws_recv(&mut w, WAIT).await, "Access denied by the server policy");

    assert!(udp_recv(&mut b, 1000).await.is_none(), "a refused attempt reached the peer");
    let calls = stub.calls();
    // one call per (token, conn_type, controller IP); the relay requests were cached
    assert_eq!(calls.len(), 2, "{calls:?}");
    assert_eq!(calls[0].authorization.as_deref(), Some("Bearer s3cret"));
    assert_eq!(calls[1].body["token"], "");

    // the hook runs after the existing checks: an unknown peer is still ID_NOT_EXIST
    let mut a = tcp_secure(&h, A_IP).await;
    let mut msg = punch_request(&h, "tok-deny");
    if let Some(rendezvous_message::Union::PunchHoleRequest(ph)) = msg.union.as_mut() {
        ph.id = "nosuchpeer".to_owned();
    }
    a.send(&msg).await.unwrap();
    match tcp_recv(&mut a, WAIT).await.and_then(|m| m.union) {
        Some(rendezvous_message::Union::PunchHoleResponse(r)) => assert_eq!(
            r.failure.enum_value(),
            Ok(punch_hole_response::Failure::ID_NOT_EXIST)
        ),
        other => panic!("expected ID_NOT_EXIST, got {other:?}"),
    }
    assert_eq!(stub.calls().len(), 2);
}

// A failed call: through without permissions by default (fail open), refused with
// AUTHZ_FAIL_CLOSED=Y. Failures are not cached.
#[tokio::test]
async fn authz_service_failure_fails_open_or_closed() {
    // nothing listens there
    let down = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        format!("http://{}/internal/hbbs/authorize", l.local_addr().unwrap())
    };
    let h = start_hbbs(port_for(8), &[("AUTHZ_URL", &down), ("AUTHZ_SECRET", "s3cret")]);
    let mut b = register_udp_peer(&h).await;
    let mut a = tcp_secure(&h, A_IP).await;
    a.send(&punch_request(&h, "tok-allow")).await.unwrap();
    let ph = punch_hole(udp_recv(&mut b, WAIT).await);
    assert_eq!(ph.control_permissions, MessageField::none());
    let mut a = tcp_secure(&h, A_IP).await;
    a.send(&relay_request(B_ID, &h.licence, "tok-allow")).await.unwrap();
    let rr = expect_forwarded_relay(udp_recv(&mut b, WAIT).await);
    assert_eq!(rr.control_permissions, MessageField::none());
    // the failure is logged, once per 30 s, without the secret or the token
    let log = wait_log(&h, &["authorization service call failed (connect error"]).await;
    assert_eq!(log.matches("authorization service call failed").count(), 1, "{log}");
    assert!(!log.contains("s3cret") && !log.contains("tok-allow"), "{log}");
    drop(h);

    let stub = authz_stub(authz_reply);
    let h = start_hbbs(
        port_for(9),
        &[("AUTHZ_URL", &stub.url), ("AUTHZ_FAIL_CLOSED", "Y")],
    );
    let mut b = register_udp_peer(&h).await;
    // a service that does not answer: refused after the 2 s timeout
    let mut a = tcp_secure(&h, A_IP).await;
    let start = Instant::now();
    a.send(&punch_request(&h, "tok-hang")).await.unwrap();
    expect_punch_failure(tcp_recv(&mut a, 5000).await, "Authorization service unavailable");
    let took = start.elapsed();
    assert!(took >= Duration::from_millis(1900) && took < Duration::from_millis(4000), "{took:?}");
    // non-200 and a malformed reply
    for token in ["tok-500", "tok-bad", "tok-500"] {
        let mut a = tcp_secure(&h, A_IP).await;
        a.send(&relay_request(B_ID, &h.licence, token)).await.unwrap();
        expect_refused(tcp_recv(&mut a, WAIT).await, "Authorization service unavailable");
    }
    assert!(udp_recv(&mut b, 500).await.is_none(), "a refused attempt reached the peer");
    // every failure asked again: none was cached
    assert_eq!(stub.calls().len(), 4);
    // a working answer still gets through
    let mut a = tcp_secure(&h, A_IP).await;
    a.send(&punch_request(&h, "tok-allow")).await.unwrap();
    let ph = punch_hole(udp_recv(&mut b, WAIT).await);
    assert_eq!(permissions_of(&ph.control_permissions), Some(PERMS));
}
