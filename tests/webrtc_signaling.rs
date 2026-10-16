//! End-to-end checks of hbbs WebRTC signaling (`WEBRTC=Y`) against the real binary.
//!
//! The harness plays both RustDesk clients the way RustDesk 1.5 does on the wire:
//! the controller (A) sends `PunchHoleRequest` with an SDP offer on a TCP or
//! WebSocket connection and keeps it open for trickle ICE; the controlled peer (B)
//! is registered over UDP or WebSocket, answers with `PunchHoleSent`/`RelayResponse`
//! on a fresh key-exchanged TCP connection and sends its ICE candidates on another
//! one. No real WebRTC stack is involved: offers, answers and candidates are opaque
//! strings to hbbs.

use hbb_common::{
    bytes::Bytes,
    futures_util::{SinkExt, StreamExt},
    protobuf::Message as _,
    rendezvous_proto::*,
    sodiumoxide::crypto::{box_, secretbox, sign},
    tcp::FramedStream,
    tokio::{self, net::TcpStream},
    try_into_v4,
    udp::FramedSocket,
    AddrMangle,
};
use std::{
    io::{Read, Write},
    net::SocketAddr,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use tokio_tungstenite::{tungstenite::Message as WsMessage, WebSocketStream};

const OFFER: &str = "webrtc://offer-envelope";
const ANSWER: &str = "webrtc://answer-envelope";
const SESSION: &str = "sha-256 97:52:D6:1F";
const B_ID: &str = "webrtcB1";
// The controlled peer uses another loopback address so hbbs does not treat the
// two clients as one intranet (that path sends FetchLocalAddr, which has no offer).
const B_IP: &str = "127.0.0.2";
const A_IP: &str = "127.0.0.1";
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
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log));
    for (k, v) in env {
        cmd.env(k, v);
    }
    let child = cmd.spawn().unwrap();
    let start = Instant::now();
    loop {
        // the listeners are bound in this order: rendezvous, NAT test/admin, WebSocket
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

/// Sends an admin command the way RD Panel does (loopback, NAT test port).
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

/// TCP rendezvous connection with the hbbs key exchange done, like `secure_tcp_required`.
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

/// True once hbbs has closed the connection (EOF or error), false on a plain timeout.
async fn tcp_closed(s: &mut FramedStream, ms: u64) -> bool {
    match tokio::time::timeout(Duration::from_millis(ms), s.next()).await {
        Ok(None) | Ok(Some(Err(_))) => true,
        Ok(Some(Ok(_))) => false,
        Err(_) => false,
    }
}

type Ws = WebSocketStream<TcpStream>;

async fn ws_connect(h: &Hbbs, local_ip: &str) -> Ws {
    let sock = tokio::net::TcpSocket::new_v4().unwrap();
    sock.bind(format!("{local_ip}:0").parse().unwrap()).unwrap();
    let stream = sock
        .connect(format!("127.0.0.1:{}", h.port + 2).parse().unwrap())
        .await
        .unwrap();
    let url = format!("ws://127.0.0.1:{}", h.port + 2);
    tokio_tungstenite::client_async(url, stream).await.unwrap().0
}

async fn ws_send(ws: &mut Ws, msg: &RendezvousMessage) {
    ws.send(WsMessage::Binary(msg.write_to_bytes().unwrap()))
        .await
        .unwrap();
}

async fn ws_recv(ws: &mut Ws, ms: u64) -> Option<RendezvousMessage> {
    let deadline = Instant::now() + Duration::from_millis(ms);
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return None;
        }
        match tokio::time::timeout(left, ws.next()).await {
            Ok(Some(Ok(WsMessage::Binary(b)))) if b.is_empty() => continue,
            Ok(Some(Ok(WsMessage::Binary(b)))) => {
                return Some(RendezvousMessage::parse_from_bytes(&b).unwrap())
            }
            Ok(Some(Ok(_))) => continue,
            _ => return None,
        }
    }
}

async fn udp_recv(s: &mut FramedSocket, ms: u64) -> Option<RendezvousMessage> {
    match s.next_timeout(ms).await {
        Some(Ok((bytes, _))) => Some(RendezvousMessage::parse_from_bytes(&bytes).unwrap()),
        _ => None,
    }
}

fn register_pk_msg() -> RendezvousMessage {
    let mut msg = RendezvousMessage::new();
    msg.set_register_pk(RegisterPk {
        id: B_ID.to_owned(),
        uuid: Bytes::from_static(b"uuid-of-peer-b"),
        pk: Bytes::from(vec![7u8; 32]),
        ..Default::default()
    });
    msg
}

/// Registers B over UDP and returns its socket.
async fn register_udp_peer(h: &Hbbs) -> FramedSocket {
    let mut s = FramedSocket::new(format!("{B_IP}:0")).await.unwrap();
    s.send(&register_pk_msg(), server(h)).await.unwrap();
    let Some(rendezvous_message::Union::RegisterPkResponse(r)) =
        udp_recv(&mut s, WAIT).await.and_then(|m| m.union)
    else {
        panic!("no RegisterPkResponse");
    };
    assert_eq!(r.result.enum_value(), Ok(register_pk_response::Result::OK));
    let mut msg = RendezvousMessage::new();
    msg.set_register_peer(RegisterPeer {
        id: B_ID.to_owned(),
        ..Default::default()
    });
    s.send(&msg, server(h)).await.unwrap();
    assert!(udp_recv(&mut s, WAIT).await.is_some(), "no RegisterPeerResponse");
    s
}

/// Registers B over WebSocket (RD Panel's WS mode); hbbs keeps its sink in ws_map.
async fn register_ws_peer(h: &Hbbs) -> Ws {
    let mut ws = ws_connect(h, B_IP).await;
    ws_send(&mut ws, &register_pk_msg()).await;
    let Some(rendezvous_message::Union::RegisterPkResponse(r)) =
        ws_recv(&mut ws, WAIT).await.and_then(|m| m.union)
    else {
        panic!("no RegisterPkResponse over ws");
    };
    assert_eq!(r.result.enum_value(), Ok(register_pk_response::Result::OK));
    ws
}

fn punch_request(h: &Hbbs, offer: &str, token: &str) -> RendezvousMessage {
    let mut msg = RendezvousMessage::new();
    msg.set_punch_hole_request(PunchHoleRequest {
        id: B_ID.to_owned(),
        licence_key: h.licence.clone(),
        version: "1.5.0".to_owned(),
        token: token.to_owned(),
        webrtc_sdp_offer: offer.to_owned(),
        ..Default::default()
    });
    msg
}

fn ice(id: &str, socket_addr: &[u8], candidate: &str) -> RendezvousMessage {
    let mut msg = RendezvousMessage::new();
    msg.set_ice_candidate(IceCandidate {
        id: id.to_owned(),
        socket_addr: Bytes::from(socket_addr.to_vec()),
        session_key: SESSION.to_owned(),
        candidate: candidate.to_owned(),
        ..Default::default()
    });
    msg
}

fn punch_hole_sent(socket_addr: Bytes, answer: &str) -> RendezvousMessage {
    let mut msg = RendezvousMessage::new();
    msg.set_punch_hole_sent(PunchHoleSent {
        socket_addr,
        id: B_ID.to_owned(),
        version: "1.5.0".to_owned(),
        webrtc_sdp_answer: answer.to_owned(),
        ..Default::default()
    });
    msg
}

fn expect_ice(msg: Option<RendezvousMessage>, candidate: &str) {
    match msg.and_then(|m| m.union) {
        Some(rendezvous_message::Union::IceCandidate(i)) => {
            assert_eq!(i.candidate, candidate);
            assert_eq!(i.session_key, SESSION);
        }
        other => panic!("expected IceCandidate {candidate}, got {other:?}"),
    }
}

#[tokio::test]
async fn webrtc_tcp_controller_udp_peer() {
    let h = start_hbbs(port_for(0), &[("WEBRTC", "Y")]);
    let mut b = register_udp_peer(&h).await;
    let mut a = tcp_secure(&h, A_IP).await;
    let a_addr = a.local_addr();

    // A -> hbbs -> B: the offer rides in PunchHole
    a.send(&punch_request(&h, OFFER, "")).await.unwrap();
    let Some(rendezvous_message::Union::PunchHole(ph)) =
        udp_recv(&mut b, WAIT).await.and_then(|m| m.union)
    else {
        panic!("B got no PunchHole");
    };
    assert_eq!(ph.webrtc_sdp_offer, OFFER);
    assert_eq!(try_into_v4(AddrMangle::decode(&ph.socket_addr)), a_addr);
    // a punch retry on the same (encrypted) connection is still understood
    a.send(&punch_request(&h, OFFER, "")).await.unwrap();
    match udp_recv(&mut b, WAIT).await.and_then(|m| m.union) {
        Some(rendezvous_message::Union::PunchHole(p)) => assert_eq!(p.webrtc_sdp_offer, OFFER),
        other => panic!("B got no PunchHole for the retry: {other:?}"),
    }

    // B's ICE connection: a candidate before the answer reaches A, which buffers it
    let mut b_ice = tcp_secure(&h, B_IP).await;
    b_ice.send(&ice("", &ph.socket_addr, "b1")).await.unwrap();
    expect_ice(tcp_recv(&mut a, WAIT).await, "b1");

    // B -> hbbs -> A: the answer rides in PunchHoleResponse
    let mut b_ans = tcp_secure(&h, B_IP).await;
    b_ans
        .send(&punch_hole_sent(ph.socket_addr.clone(), ANSWER))
        .await
        .unwrap();
    match tcp_recv(&mut a, WAIT).await.and_then(|m| m.union) {
        Some(rendezvous_message::Union::PunchHoleResponse(r)) => {
            assert_eq!(r.webrtc_sdp_answer, ANSWER);
            assert!(!r.socket_addr.is_empty());
        }
        other => panic!("A got no PunchHoleResponse: {other:?}"),
    }

    // after the response A's punch connection still routes ICE both ways
    b_ice.send(&ice("", &ph.socket_addr, "b2")).await.unwrap();
    expect_ice(tcp_recv(&mut a, WAIT).await, "b2");
    a.send(&ice(B_ID, &[], "a1")).await.unwrap();
    expect_ice(udp_recv(&mut b, WAIT).await, "a1");

    // A cannot send candidates to a peer it did not punch to; the connection stays up
    a.send(&ice("someoneelse", &[], "x")).await.unwrap();
    a.send(&ice(B_ID, &[], "a2")).await.unwrap();
    expect_ice(udp_recv(&mut b, WAIT).await, "a2");

    // candidates addressed to an unknown controller go nowhere
    let bogus = AddrMangle::encode("127.0.0.9:9".parse().unwrap());
    b_ice.send(&ice("", &bogus, "lost")).await.unwrap();
    b_ice.send(&ice("", &ph.socket_addr, "b3")).await.unwrap();
    expect_ice(tcp_recv(&mut a, WAIT).await, "b3");

    // once A hangs up its route is gone
    drop(a);
    tokio::time::sleep(Duration::from_millis(300)).await;
    b_ice.send(&ice("", &ph.socket_addr, "late")).await.unwrap();
    assert!(!tcp_closed(&mut b_ice, 300).await);
}

#[tokio::test]
async fn webrtc_ws_controller_ws_peer_relay_answer() {
    let h = start_hbbs(port_for(1), &[("WEBRTC", "Y")]);
    let mut b = register_ws_peer(&h).await;
    let mut a = ws_connect(&h, A_IP).await;

    ws_send(&mut a, &punch_request(&h, OFFER, "")).await;
    let Some(rendezvous_message::Union::PunchHole(ph)) =
        ws_recv(&mut b, WAIT).await.and_then(|m| m.union)
    else {
        panic!("B got no PunchHole over ws");
    };
    assert_eq!(ph.webrtc_sdp_offer, OFFER);

    // relay path: B answers with RelayResponse (create_relay in the client)
    let mut b_ans = tcp_secure(&h, B_IP).await;
    let mut rr = RelayResponse {
        socket_addr: ph.socket_addr.clone(),
        uuid: "relay-uuid".to_owned(),
        version: "1.5.0".to_owned(),
        webrtc_sdp_answer: ANSWER.to_owned(),
        ..Default::default()
    };
    rr.set_id(B_ID.to_owned());
    let mut msg = RendezvousMessage::new();
    msg.set_relay_response(rr);
    b_ans.send(&msg).await.unwrap();
    match ws_recv(&mut a, WAIT).await.and_then(|m| m.union) {
        Some(rendezvous_message::Union::RelayResponse(r)) => {
            assert_eq!(r.webrtc_sdp_answer, ANSWER);
            assert_eq!(r.uuid, "relay-uuid");
        }
        other => panic!("A got no RelayResponse: {other:?}"),
    }

    // ICE both ways: B over TCP to A's ws, A over ws to B's ws sink
    let mut b_ice = tcp_secure(&h, B_IP).await;
    b_ice.send(&ice("", &ph.socket_addr, "b1")).await.unwrap();
    expect_ice(ws_recv(&mut a, WAIT).await, "b1");
    ws_send(&mut a, &ice(B_ID, &[], "a1")).await;
    expect_ice(ws_recv(&mut b, WAIT).await, "a1");
    // B's ws sink survived the forwarded offer and still gets candidates
    ws_send(&mut a, &ice(B_ID, &[], "a2")).await;
    expect_ice(ws_recv(&mut b, WAIT).await, "a2");
}

#[tokio::test]
async fn webrtc_off_behaves_like_upstream_and_admin_toggle() {
    let h = start_hbbs(port_for(2), &[]);
    assert!(admin(&h, "webrtc").contains("WEBRTC: false"));
    let mut b = register_udp_peer(&h).await;
    let mut a = tcp_secure(&h, A_IP).await;

    a.send(&punch_request(&h, OFFER, "")).await.unwrap();
    let Some(rendezvous_message::Union::PunchHole(ph)) =
        udp_recv(&mut b, WAIT).await.and_then(|m| m.union)
    else {
        panic!("B got no PunchHole");
    };
    assert!(ph.webrtc_sdp_offer.is_empty());
    assert!(!ph.force_relay);

    // an IceCandidate is an unknown message: hbbs closes the connection
    let mut b_ice = tcp_secure(&h, B_IP).await;
    b_ice.send(&ice("", &ph.socket_addr, "b1")).await.unwrap();
    assert!(tcp_closed(&mut b_ice, WAIT).await);

    // the answer is dropped from PunchHoleResponse
    let mut b_ans = tcp_secure(&h, B_IP).await;
    b_ans
        .send(&punch_hole_sent(ph.socket_addr.clone(), ANSWER))
        .await
        .unwrap();
    match tcp_recv(&mut a, WAIT).await.and_then(|m| m.union) {
        Some(rendezvous_message::Union::PunchHoleResponse(r)) => {
            assert!(r.webrtc_sdp_answer.is_empty())
        }
        other => panic!("A got no PunchHoleResponse: {other:?}"),
    }

    // admin command turns it on at runtime
    admin(&h, "webrtc Y");
    assert!(admin(&h, "wr").contains("WEBRTC: true"));
    assert!(admin(&h, "h").contains("webrtc(wr) [Y|N]"));
    let mut a2 = tcp_secure(&h, A_IP).await;
    a2.send(&punch_request(&h, OFFER, "")).await.unwrap();
    let Some(rendezvous_message::Union::PunchHole(ph)) =
        udp_recv(&mut b, WAIT).await.and_then(|m| m.union)
    else {
        panic!("B got no PunchHole");
    };
    assert_eq!(ph.webrtc_sdp_offer, OFFER);

    // ALWAYS_USE_RELAY drops the offer: a WebRTC pair can be direct
    admin(&h, "aur Y");
    let mut a3 = tcp_secure(&h, A_IP).await;
    a3.send(&punch_request(&h, OFFER, "")).await.unwrap();
    let Some(rendezvous_message::Union::PunchHole(ph)) =
        udp_recv(&mut b, WAIT).await.and_then(|m| m.union)
    else {
        panic!("B got no PunchHole");
    };
    assert!(ph.webrtc_sdp_offer.is_empty());
}

#[tokio::test]
async fn webrtc_respects_must_login() {
    let h = start_hbbs(port_for(3), &[("WEBRTC", "Y"), ("MUST_LOGIN", "Y")]);
    let mut b = register_udp_peer(&h).await;
    let mut a = tcp_secure(&h, A_IP).await;

    a.send(&punch_request(&h, OFFER, "")).await.unwrap();
    match tcp_recv(&mut a, WAIT).await.and_then(|m| m.union) {
        Some(rendezvous_message::Union::PunchHoleResponse(r)) => {
            assert!(!r.other_failure.is_empty())
        }
        other => panic!("expected a login failure, got {other:?}"),
    }
    // no route was created, so candidates from A go nowhere
    a.send(&ice(B_ID, &[], "a1")).await.unwrap();
    assert!(udp_recv(&mut b, 1000).await.is_none());

    // with a token (no JWT key configured, any token passes) the offer is forwarded
    let mut a2 = tcp_secure(&h, A_IP).await;
    a2.send(&punch_request(&h, OFFER, "token")).await.unwrap();
    let Some(rendezvous_message::Union::PunchHole(ph)) =
        udp_recv(&mut b, WAIT).await.and_then(|m| m.union)
    else {
        panic!("B got no PunchHole");
    };
    assert_eq!(ph.webrtc_sdp_offer, OFFER);
}
