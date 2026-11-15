//! End-to-end checks of the opt-in key exchange version 1 (`KEY_EXCHANGE_V1`) against the real
//! hbbs binary: version 0 on the wire when it is off, a version 1 handshake that round-trips an
//! encrypted request over TCP (and over WebSocket with `WS_KEY_EXCHANGE`), a legacy client that
//! answers version 0, refused or failing tampered picks, and a plain first message that still
//! reaches the normal handler.
//!
//! The client side is what RustDesk 1.5.x does (rustdesk/rustdesk#16326, `key_exchange` in
//! `src/common.rs`), written against hbb_common's helpers (`kx_version_for`, `KxTranscript`,
//! `Encrypt::new_split`, `FramedStream::set_key_split`), so the derivation is checked against
//! the library code the real client uses. No RustDesk client binary is involved.

use hbb_common::{
    bytes::{Bytes, BytesMut},
    futures_util::{SinkExt, StreamExt},
    protobuf::Message as _,
    rendezvous_proto::*,
    sodiumoxide::crypto::{box_, secretbox, sign},
    tcp::{self, Encrypt, FramedStream, KxTranscript},
    tokio::{self, net::TcpStream},
};
use std::{
    net::SocketAddr,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use tokio_tungstenite::{tungstenite::Message as WsMessage, WebSocketStream};

const WAIT: u64 = 3000;

struct Hbbs {
    child: Child,
    port: u16,
    dir: tempfile::TempDir,
    pk: sign::PublicKey,
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
        .env_remove("WS_KEY_EXCHANGE")
        .env_remove("KEY_EXCHANGE_V1")
        .env_remove("TRUSTED_PROXIES")
        .env_remove("WS_RELAY_SERVERS")
        .env_remove("AUTHZ_URL")
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
    let pk = sign::PublicKey::from_slice(&base64::decode(&licence).unwrap()).unwrap();
    Hbbs {
        child,
        port,
        dir,
        pk,
    }
}

/// Distinct port blocks per test so the tests can run in parallel (below the ephemeral range).
fn port_for(slot: u16) -> u16 {
    24000 + (std::process::id() % 200) as u16 * 50 + slot * 5
}

fn server(h: &Hbbs) -> SocketAddr {
    format!("127.0.0.1:{}", h.port).parse().unwrap()
}

/// What a 1.5.x client does with the server's KeyExchange before it replies, as in
/// `key_exchange` in rustdesk's `src/common.rs`: verify the signed key and, when the key carries
/// the signed-parameters marker (bit 255) or the message carries parameters, verify them too.
/// Returns the server's key as signed.
fn client_verify_offer(ex: &KeyExchange, rs_pk: &sign::PublicKey) -> Result<[u8; 32], String> {
    if ex.keys.len() != 1 {
        return Err("not a phase 1 key exchange".into());
    }
    let their_pk: [u8; 32] = sign::verify(&ex.keys[0], rs_pk)
        .map_err(|_| "Signature mismatch in key exchange".to_owned())?
        .try_into()
        .map_err(|_| "Wrong their public length in key exchange".to_owned())?;
    if their_pk[31] & 0x80 != 0 || !ex.signed_params.is_empty() {
        let params = sign::verify(&ex.signed_params, rs_pk)
            .ok()
            .and_then(|signed| {
                let params = signed.strip_prefix(tcp::KX_PARAMS_DOMAIN)?;
                KxParams::parse_from_bytes(params).ok()
            })
            .ok_or("Missing or invalid signed key exchange parameters")?;
        if params.pk[..] != their_pk[..] || params.version != ex.version {
            return Err("Key exchange version or public key does not match its signature".into());
        }
    }
    Ok(their_pk)
}

/// The client's answer: the KeyExchange to send and the key it seals.
struct Answer {
    msg: KeyExchange,
    key: secretbox::Key,
    initiator_pk: Bytes,
    server_pk: [u8; 32],
    advertised: u32,
}

impl Answer {
    /// `sent` is the version written into the message; the keys follow `picked`.
    fn new(ex: &KeyExchange, server_pk: [u8; 32], sent: u32) -> Self {
        let (our_pk, our_sk) = box_::gen_keypair();
        let key = secretbox::gen_key();
        let nonce = box_::Nonce([0u8; box_::NONCEBYTES]);
        let sealed = box_::seal(&key.0, &nonce, &box_::PublicKey(server_pk), &our_sk);
        let initiator_pk = Bytes::from(our_pk.0.to_vec());
        Self {
            msg: KeyExchange {
                keys: vec![initiator_pk.clone(), Bytes::from(sealed)],
                version: sent,
                ..Default::default()
            },
            key,
            initiator_pk,
            server_pk,
            advertised: ex.version,
        }
    }

    fn transcript(&self, picked: u32) -> KxTranscript<'_> {
        KxTranscript {
            initiator_pk: &self.initiator_pk,
            responder_pk: &self.server_pk,
            advertised: self.advertised,
            picked,
        }
    }

    /// The client's cipher for keys derived at version `picked`.
    fn cipher(&self, picked: u32) -> Encrypt {
        match picked {
            0 => Encrypt::new(self.key.clone()),
            _ => Encrypt::new_split(self.key.clone(), true, &self.transcript(picked)).unwrap(),
        }
    }
}

/// The 1.5.x client's answer: picks the highest version both speak.
fn real_client_answer(ex: &KeyExchange, rs_pk: &sign::PublicKey) -> Result<Answer, String> {
    let server_pk = client_verify_offer(ex, rs_pk)?;
    let picked = tcp::kx_version_for(ex.version);
    Ok(Answer::new(ex, server_pk, picked))
}

/// The requests the tests send; the first two keep the connection open, so several can follow
/// each other under the advancing nonces. An OnlineRequest is answered, then hbbs closes.
#[derive(Clone, Copy)]
enum Req {
    Online,
    RegisterPk,
    RegisterPeer,
}

const KX_ID: &str = "kxclient1";

fn request(req: Req) -> Vec<u8> {
    let mut msg = RendezvousMessage::new();
    match req {
        Req::Online => msg.set_online_request(OnlineRequest {
            id: KX_ID.to_owned(),
            peers: vec!["nosuchpeer".to_owned()],
            ..Default::default()
        }),
        Req::RegisterPk => msg.set_register_pk(RegisterPk {
            id: KX_ID.to_owned(),
            uuid: Bytes::from(format!("uuid-of-{KX_ID}").into_bytes()),
            pk: Bytes::from(vec![7u8; 32]),
            ..Default::default()
        }),
        Req::RegisterPeer => msg.set_register_peer(RegisterPeer {
            id: KX_ID.to_owned(),
            ..Default::default()
        }),
    }
    msg.write_to_bytes().unwrap()
}

fn answered(req: Req, bytes: &[u8]) -> bool {
    use rendezvous_message::Union::*;
    let union = RendezvousMessage::parse_from_bytes(bytes).ok().and_then(|m| m.union);
    match (req, union) {
        (Req::Online, Some(OnlineResponse(_))) => true,
        (Req::RegisterPk, Some(RegisterPkResponse(r))) => {
            r.result.enum_value() == Ok(register_pk_response::Result::OK)
        }
        (Req::RegisterPeer, Some(RegisterPeerResponse(_))) => true,
        _ => false,
    }
}

async fn tcp_connect(h: &Hbbs) -> FramedStream {
    FramedStream::new(server(h), None, WAIT).await.unwrap()
}

/// The first frame of a connection, as bytes and as the KeyExchange it must be.
async fn tcp_offer(s: &mut FramedStream) -> (Vec<u8>, KeyExchange) {
    let bytes = s.next_timeout(WAIT).await.unwrap().unwrap();
    let msg = RendezvousMessage::parse_from_bytes(&bytes).unwrap();
    let Some(rendezvous_message::Union::KeyExchange(ex)) = msg.union else {
        panic!("expected KeyExchange, got {msg:?}");
    };
    (bytes.to_vec(), ex)
}

/// Sends a request through the stream's cipher; whether its answer came back.
async fn tcp_round_trip(s: &mut FramedStream, req: Req) -> bool {
    if s.send_raw(request(req)).await.is_err() {
        return false;
    }
    let deadline = Instant::now() + Duration::from_millis(WAIT);
    loop {
        let left = deadline.saturating_duration_since(Instant::now()).as_millis() as u64;
        if left == 0 {
            return false;
        }
        match s.next_timeout(left).await {
            Some(Ok(bytes)) if bytes.is_empty() => continue,
            Some(Ok(bytes)) => return answered(req, &bytes),
            _ => return false,
        }
    }
}

/// Whether the server closed the connection (or failed it) without sending anything more.
async fn tcp_closed_silently(s: &mut FramedStream) -> bool {
    loop {
        match s.next_timeout(WAIT).await {
            Some(Ok(bytes)) if bytes.is_empty() => continue,
            Some(Ok(_)) => return false,
            _ => return true,
        }
    }
}

// Off by default: the offer is what it has always been, a version 0 exchange, and a client
// that answers the way it always has (or even one that names version 1 anyway: the field is
// not looked at without the option) gets the same single-key connection.
#[tokio::test]
async fn version_0_on_the_wire_when_off() {
    let h = start_hbbs(port_for(0), &[]);
    let mut s = tcp_connect(&h).await;
    let (raw, ex) = tcp_offer(&mut s).await;
    assert_eq!(ex.keys.len(), 1);
    assert_eq!(ex.version, 0);
    assert!(ex.signed_params.is_empty());
    // nothing else is on the wire: the message is the signed key and nothing more
    let only_key = RendezvousMessage {
        union: Some(rendezvous_message::Union::KeyExchange(KeyExchange {
            keys: ex.keys.clone(),
            ..Default::default()
        })),
        ..Default::default()
    };
    assert_eq!(raw, only_key.write_to_bytes().unwrap());
    let pk = client_verify_offer(&ex, &h.pk).unwrap();
    assert_eq!(pk[31] & 0x80, 0, "a version 0 key never carries the marker");

    let answer = real_client_answer(&ex, &h.pk).unwrap();
    assert_eq!(answer.msg.version, 0);
    s.send(&RendezvousMessage {
        union: Some(rendezvous_message::Union::KeyExchange(answer.msg.clone())),
        ..Default::default()
    })
    .await
    .unwrap();
    s.set_key(answer.key.clone());
    assert!(tcp_round_trip(&mut s, Req::RegisterPk).await, "version 0 round trip failed");

    // a client that names version 1 without having been offered it: as before, version 0
    let mut s = tcp_connect(&h).await;
    let (_, ex) = tcp_offer(&mut s).await;
    let answer = Answer::new(&ex, client_verify_offer(&ex, &h.pk).unwrap(), 1);
    s.send(&RendezvousMessage {
        union: Some(rendezvous_message::Union::KeyExchange(answer.msg.clone())),
        ..Default::default()
    })
    .await
    .unwrap();
    s.set_key(answer.key.clone());
    assert!(tcp_round_trip(&mut s, Req::RegisterPk).await, "the version field is ignored when off");
}

// With the option on the offer carries version 1 and signed parameters, and a 1.5.x client
// derives the same per-direction keys: an encrypted request gets an encrypted answer.
#[tokio::test]
async fn version_1_handshake_round_trips_over_tcp() {
    let h = start_hbbs(port_for(1), &[("KEY_EXCHANGE_V1", "Y")]);
    let mut s = tcp_connect(&h).await;
    let (_, ex) = tcp_offer(&mut s).await;
    assert_eq!(ex.version, 1);
    assert!(!ex.signed_params.is_empty());
    let pk = client_verify_offer(&ex, &h.pk).unwrap();
    assert_ne!(pk[31] & 0x80, 0, "the signed-parameters marker is set");

    let answer = real_client_answer(&ex, &h.pk).unwrap();
    assert_eq!(answer.msg.version, 1);
    s.send(&RendezvousMessage {
        union: Some(rendezvous_message::Union::KeyExchange(answer.msg.clone())),
        ..Default::default()
    })
    .await
    .unwrap();
    // hbb_common's own client-side helper: sender of the sealed key is the initiator
    s.set_key_split(answer.key.clone(), true, &answer.transcript(1)).unwrap();
    assert!(tcp_round_trip(&mut s, Req::RegisterPk).await, "version 1 round trip failed");
    assert!(
        tcp_round_trip(&mut s, Req::RegisterPeer).await,
        "second request under advancing nonces failed"
    );
    assert!(tcp_round_trip(&mut s, Req::Online).await, "third request failed");
}

// A client from before versions ignores the parameters, uses the key as signed (X25519 ignores
// bit 255) and answers version 0; hbbs then speaks the single-key scheme with it.
#[tokio::test]
async fn legacy_client_answering_version_0_still_works() {
    let h = start_hbbs(port_for(2), &[("KEY_EXCHANGE_V1", "Y")]);
    let mut s = tcp_connect(&h).await;
    let (_, ex) = tcp_offer(&mut s).await;
    // what a 1.4.x client does: verify the signature of keys[0] only
    let server_pk: [u8; 32] = sign::verify(&ex.keys[0], &h.pk).unwrap().try_into().unwrap();
    let answer = Answer::new(&ex, server_pk, 0);
    assert_eq!(answer.msg.version, 0);
    s.send(&RendezvousMessage {
        union: Some(rendezvous_message::Union::KeyExchange(answer.msg.clone())),
        ..Default::default()
    })
    .await
    .unwrap();
    s.set_key(answer.key.clone());
    assert!(tcp_round_trip(&mut s, Req::RegisterPk).await, "legacy client round trip failed");
}

// A pick above what was offered is refused on the spot; a pick that was rewritten in transit
// (the client's keys follow the version it chose, the server's follow the one it received)
// leaves the two sides on different keys, so nothing is ever answered.
#[tokio::test]
async fn tampered_picks_are_refused() {
    let h = start_hbbs(port_for(3), &[("KEY_EXCHANGE_V1", "Y")]);

    // unsupported version: refused, nothing answered
    let mut s = tcp_connect(&h).await;
    let (_, ex) = tcp_offer(&mut s).await;
    let answer = Answer::new(&ex, client_verify_offer(&ex, &h.pk).unwrap(), 2);
    s.send(&RendezvousMessage {
        union: Some(rendezvous_message::Union::KeyExchange(answer.msg.clone())),
        ..Default::default()
    })
    .await
    .unwrap();
    assert!(tcp_closed_silently(&mut s).await, "an unsupported pick was not refused");

    // a version 1 client whose pick was lowered to 0 on the way (downgrade)
    let mut s = tcp_connect(&h).await;
    let (_, ex) = tcp_offer(&mut s).await;
    let answer = Answer::new(&ex, client_verify_offer(&ex, &h.pk).unwrap(), 0);
    s.send(&RendezvousMessage {
        union: Some(rendezvous_message::Union::KeyExchange(answer.msg.clone())),
        ..Default::default()
    })
    .await
    .unwrap();
    // the client believes it picked 1 and keeps its version 1 keys
    s.set_key_split(answer.key.clone(), true, &answer.transcript(1)).unwrap();
    assert!(!tcp_round_trip(&mut s, Req::RegisterPk).await, "a downgraded pick was accepted");

    // a version 0 client whose pick was raised to 1 on the way
    let mut s = tcp_connect(&h).await;
    let (_, ex) = tcp_offer(&mut s).await;
    let answer = Answer::new(&ex, client_verify_offer(&ex, &h.pk).unwrap(), 1);
    s.send(&RendezvousMessage {
        union: Some(rendezvous_message::Union::KeyExchange(answer.msg.clone())),
        ..Default::default()
    })
    .await
    .unwrap();
    s.set_key(answer.key.clone());
    assert!(!tcp_round_trip(&mut s, Req::RegisterPk).await, "a raised pick was accepted");

    // the offer a downgrading middlebox would have to forge is signed: stripping the
    // parameters or lowering the version is caught by the client before it answers
    let mut s = tcp_connect(&h).await;
    let (_, ex) = tcp_offer(&mut s).await;
    let mut lowered = ex.clone();
    lowered.version = 0;
    assert!(client_verify_offer(&lowered, &h.pk).is_err());
    let mut stripped = ex.clone();
    stripped.version = 0;
    stripped.signed_params = Bytes::new();
    assert!(client_verify_offer(&stripped, &h.pk).is_err());
}

// A client that does not do the exchange at all (no account, so no handshake) sends its
// request as the first message; it reaches the normal handler, answered in the clear.
#[tokio::test]
async fn plain_first_message_still_reaches_the_handler() {
    let h = start_hbbs(port_for(4), &[("KEY_EXCHANGE_V1", "Y")]);
    let mut s = tcp_connect(&h).await;
    let (_, ex) = tcp_offer(&mut s).await;
    assert_eq!(ex.version, 1);
    assert!(tcp_round_trip(&mut s, Req::RegisterPk).await, "plain request after the offer failed");
}

type Ws = WebSocketStream<TcpStream>;

async fn ws_connect(h: &Hbbs) -> Ws {
    let stream = TcpStream::connect(("127.0.0.1", h.port + 2)).await.unwrap();
    tokio_tungstenite::client_async(format!("ws://127.0.0.1:{}", h.port + 2), stream)
        .await
        .unwrap()
        .0
}

async fn ws_frame(ws: &mut Ws, ms: u64) -> Option<Vec<u8>> {
    let deadline = Instant::now() + Duration::from_millis(ms);
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return None;
        }
        match tokio::time::timeout(left, ws.next()).await {
            Ok(Some(Ok(WsMessage::Binary(b)))) => return Some(b.to_vec()),
            Ok(Some(Ok(_))) => continue,
            _ => return None,
        }
    }
}

// KEY_EXCHANGE_V1 changes what is advertised where hbbs already advertises: TCP always, and
// WebSocket only with WS_KEY_EXCHANGE too.
#[tokio::test]
async fn websocket_offers_version_1_only_with_ws_key_exchange() {
    let h = start_hbbs(port_for(5), &[("KEY_EXCHANGE_V1", "Y")]);
    let mut ws = ws_connect(&h).await;
    assert!(ws_frame(&mut ws, 700).await.is_none(), "an offer went out on WebSocket");
    let mut s = tcp_connect(&h).await;
    assert_eq!(tcp_offer(&mut s).await.1.version, 1);

    let h = start_hbbs(port_for(6), &[("KEY_EXCHANGE_V1", "Y"), ("WS_KEY_EXCHANGE", "Y")]);
    let mut ws = ws_connect(&h).await;
    let raw = ws_frame(&mut ws, WAIT).await.expect("no offer on WebSocket");
    let msg = RendezvousMessage::parse_from_bytes(&raw).unwrap();
    let Some(rendezvous_message::Union::KeyExchange(ex)) = msg.union else {
        panic!("expected KeyExchange, got {msg:?}");
    };
    assert_eq!(ex.version, 1);
    let answer = real_client_answer(&ex, &h.pk).unwrap();
    let mut cipher = answer.cipher(1);
    ws.send(WsMessage::Binary(
        RendezvousMessage {
            union: Some(rendezvous_message::Union::KeyExchange(answer.msg.clone())),
            ..Default::default()
        }
        .write_to_bytes()
        .unwrap()
        .into(),
    ))
    .await
    .unwrap();
    for req in [Req::RegisterPk, Req::RegisterPeer, Req::Online] {
        ws.send(WsMessage::Binary(cipher.enc(&request(req)).into()))
            .await
            .unwrap();
        let reply = loop {
            let raw = ws_frame(&mut ws, WAIT).await.expect("no encrypted answer on WebSocket");
            if raw.is_empty() {
                continue;
            }
            break raw;
        };
        let mut bytes = BytesMut::from(&reply[..]);
        cipher.dec(&mut bytes).unwrap();
        assert!(answered(req, &bytes));
    }
}
