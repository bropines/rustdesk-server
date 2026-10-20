//! Opt-in authorization hook (`AUTHZ_URL`).
//!
//! Upstream hbbs forwards every connection attempt that passes the licence key and
//! `MUST_LOGIN` checks to the peer; whether it is accepted is then up to the device's own
//! settings. With `AUTHZ_URL` set, hbbs first asks an HTTP service (e.g. RD Panel) about
//! each `PunchHoleRequest` and client `RequestRelay` it is about to forward:
//!
//! ```text
//! POST <AUTHZ_URL>
//! Authorization: Bearer <AUTHZ_SECRET>
//! Content-Type: application/json
//!
//! {"target_id":"<peer id>","token":"<controller token, may be empty>","conn_type":<ConnType>,
//!  "controller_ip":"<controller IP as hbbs sees it>","kind":"punch_hole"|"request_relay"}
//! ```
//!
//! The service answers 200 with `{"allow":bool,"permissions":"<u64>","reason":"<text>"}`:
//! - `allow: false`: the controller gets `reason` (or a default) as the refusal and
//!   nothing reaches the peer;
//! - `allow: true`: forwarded as usual; non-zero `permissions` are set as the
//!   `ControlPermissions` of the PunchHole/FetchLocalAddr/RequestRelay sent to the peer
//!   (RustDesk's layout: 2 bits per `Permission` value, 1 = disable, 2 = enable), absent
//!   or 0 leaves the field unset.
//!
//! Decisions are cached for 15 s per (peer, token, conn_type, controller IP), so the
//! RequestRelay that follows a failed punch costs nothing. A failed call (2 s timeout,
//! connection error, non-200, malformed reply) is not cached: the attempt goes through
//! without permissions, as with the hook off, unless `AUTHZ_FAIL_CLOSED=Y`, which refuses
//! it. Failures are logged at most every 30 s. Neither the secret nor tokens are ever
//! logged; the cache keeps a SHA-256 of the token, not the token.
//!
//! `AUTHZ_URL` empty (default): no call, nothing changes, as upstream.

use crate::common::get_arg;
use hbb_common::{
    anyhow::anyhow,
    bail, log,
    protobuf::MessageField,
    rendezvous_proto::{
        rendezvous_message, ControlPermissions, PunchHoleResponse, RelayResponse,
        RendezvousMessage,
    },
    sha2::{Digest, Sha256},
    timeout, ResultType,
};
use once_cell::sync::OnceCell;
use serde_derive::Deserialize;
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Mutex,
    time::{Duration, Instant},
};

// The whole call, connect to the last byte of the reply. An uncached decision delays
// the punch request by at most this much.
const CALL_TIMEOUT_MS: u64 = 2_000;
const CACHE_TTL: Duration = Duration::from_secs(15);
const CACHE_MAX: usize = 10_000;
const ERROR_LOG_INTERVAL: Duration = Duration::from_secs(30);
// A reply is a few dozen bytes; more is not the authorization service.
const MAX_REPLY_LEN: usize = 16 * 1024;
// The reason is shown to the controller's user.
const MAX_REASON_LEN: usize = 256;
pub(crate) const DENIED: &str = "Access denied by the server policy";
pub(crate) const UNAVAILABLE: &str = "Authorization service unavailable";

static AUTHZ: OnceCell<Authz> = OnceCell::new();

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    PunchHole,
    RequestRelay,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Kind::PunchHole => "punch_hole",
            Kind::RequestRelay => "request_relay",
        }
    }
}

/// A connection attempt hbbs is about to forward to a peer.
pub(crate) struct Attempt<'a> {
    pub target_id: &'a str,
    // the controller's login token; never logged
    pub token: &'a str,
    pub conn_type: i32,
    pub controller_ip: IpAddr,
    pub kind: Kind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// Forward the attempt; non-zero: the peer's `ControlPermissions`.
    Allow(u64),
    /// Refuse it with this reason for the controller; nothing goes to the peer.
    Deny(String),
}

/// The decision for `attempt`. With `AUTHZ_URL` unset always `Allow(0)`, as upstream.
/// Never called with a lock held: it may wait for the service (at most 2 s).
pub(crate) async fn authorize(attempt: &Attempt<'_>) -> Verdict {
    match AUTHZ.get() {
        Some(authz) => authz.check(attempt).await,
        None => Verdict::Allow(0),
    }
}

/// The refusal for the controller, as for the other checks: `PunchHoleResponse.other_failure`
/// for a punch request, `RelayResponse.refuse_reason` for a relay request.
pub(crate) fn refusal(kind: Kind, reason: String) -> RendezvousMessage {
    let mut msg = RendezvousMessage::new();
    match kind {
        Kind::PunchHole => msg.set_punch_hole_response(PunchHoleResponse {
            other_failure: reason,
            ..Default::default()
        }),
        Kind::RequestRelay => msg.set_relay_response(RelayResponse {
            refuse_reason: reason,
            ..Default::default()
        }),
    }
    msg
}

/// Puts an allowed attempt's permissions on the message for the peer (PunchHole,
/// FetchLocalAddr or RequestRelay); 0 leaves the field unset.
pub(crate) fn set_permissions(msg: &mut RendezvousMessage, permissions: u64) {
    let field = if permissions == 0 {
        MessageField::none()
    } else {
        MessageField::some(ControlPermissions {
            permissions,
            ..Default::default()
        })
    };
    match msg.union.as_mut() {
        Some(rendezvous_message::Union::PunchHole(m)) => m.control_permissions = field,
        Some(rendezvous_message::Union::FetchLocalAddr(m)) => m.control_permissions = field,
        Some(rendezvous_message::Union::RequestRelay(m)) => m.control_permissions = field,
        _ => {}
    }
}

/// Reads `AUTHZ_URL`, `AUTHZ_SECRET` / `AUTHZ_SECRET_FILE` and `AUTHZ_FAIL_CLOSED` (env
/// or flags) once at start. An invalid URL or an unreadable secret file stops hbbs: the
/// hook was asked for, and running without it would let every connection through.
pub(crate) fn init() -> ResultType<()> {
    let url = get_arg("authz-url");
    let url = url.trim();
    if url.is_empty() {
        log::info!("AUTHZ_URL= (off)");
        return Ok(());
    }
    let file = get_arg("authz-secret-file");
    let file = file.trim();
    let secret = if file.is_empty() {
        get_arg("authz-secret")
    } else {
        std::fs::read_to_string(file)
            .map_err(|e| anyhow!("cannot read AUTHZ_SECRET_FILE {}: {}", file, e))?
    };
    let secret = secret.trim().to_owned();
    let fail_closed = get_arg("authz-fail-closed").trim().eq_ignore_ascii_case("y");
    let no_secret = secret.is_empty();
    let authz = Authz::new(url, secret, fail_closed)?;
    log::info!(
        "AUTHZ_URL={} AUTHZ_FAIL_CLOSED={}",
        url_for_log(&authz.url),
        if fail_closed { "Y" } else { "N" }
    );
    if no_secret {
        log::warn!("AUTHZ_URL is set without AUTHZ_SECRET/AUTHZ_SECRET_FILE: calls carry no Authorization header");
    }
    AUTHZ.set(authz).ok();
    Ok(())
}

/// The URL without credentials or query, for the log.
fn url_for_log(url: &reqwest::Url) -> String {
    let mut url = url.clone();
    url.set_username("").ok();
    url.set_password(None).ok();
    url.set_query(None);
    url.set_fragment(None);
    url.to_string()
}

struct Authz {
    url: reqwest::Url,
    secret: String,
    fail_closed: bool,
    client: reqwest::Client,
    cache: Mutex<Cache>,
    last_error_log: Mutex<Option<Instant>>,
}

impl Authz {
    fn new(url: &str, secret: String, fail_closed: bool) -> ResultType<Self> {
        let url = reqwest::Url::parse(url).map_err(|e| anyhow!("invalid AUTHZ_URL: {}", e))?;
        if !matches!(url.scheme(), "http" | "https") {
            bail!("invalid AUTHZ_URL: not an http(s) URL");
        }
        let client = reqwest::Client::builder()
            // The bearer secret goes to AUTHZ_URL only: no proxy from HTTP(S)_PROXY, no
            // redirects (a redirect is a failed call).
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_millis(CALL_TIMEOUT_MS))
            .timeout(Duration::from_millis(CALL_TIMEOUT_MS))
            .build()?;
        Ok(Self {
            url,
            secret,
            fail_closed,
            client,
            cache: Default::default(),
            last_error_log: Default::default(),
        })
    }

    async fn check(&self, attempt: &Attempt<'_>) -> Verdict {
        let key = Key::new(attempt);
        // the cache lock is never held across the call
        let cached = self
            .cache
            .lock()
            .ok()
            .and_then(|mut cache| cache.get(&key, Instant::now()));
        let (verdict, how) = match cached {
            Some(verdict) => (verdict, "cached"),
            None => match self.call(attempt).await {
                Ok(verdict) => {
                    if let Ok(mut cache) = self.cache.lock() {
                        cache.insert(key, verdict.clone(), Instant::now());
                    }
                    (verdict, "service")
                }
                Err(why) => {
                    self.log_error(&why);
                    (self.on_error(), "service failed")
                }
            },
        };
        match &verdict {
            Verdict::Allow(permissions) => log::debug!(
                "AUTHZ: {} from {} to {} allowed ({}{})",
                attempt.kind.as_str(),
                attempt.controller_ip,
                attempt.target_id,
                how,
                if *permissions != 0 { ", permissions set" } else { "" }
            ),
            Verdict::Deny(reason) => log::info!(
                "AUTHZ: {} from {} to {} refused ({}): {}",
                attempt.kind.as_str(),
                attempt.controller_ip,
                attempt.target_id,
                how,
                reason
            ),
        }
        verdict
    }

    fn on_error(&self) -> Verdict {
        if self.fail_closed {
            Verdict::Deny(UNAVAILABLE.to_owned())
        } else {
            Verdict::Allow(0)
        }
    }

    async fn call(&self, attempt: &Attempt<'_>) -> Result<Verdict, String> {
        let body = serde_json::json!({
            "target_id": attempt.target_id,
            "token": attempt.token,
            "conn_type": attempt.conn_type,
            "controller_ip": attempt.controller_ip.to_string(),
            "kind": attempt.kind.as_str(),
        });
        let mut request = self.client.post(self.url.clone()).json(&body);
        if !self.secret.is_empty() {
            request = request.bearer_auth(&self.secret);
        }
        let call = async {
            let mut response = request.send().await.map_err(describe)?;
            if response.status() != reqwest::StatusCode::OK {
                return Err(format!("HTTP status {}", response.status().as_u16()));
            }
            let mut reply = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(describe)? {
                if reply.len() + chunk.len() > MAX_REPLY_LEN {
                    return Err("reply too large".to_owned());
                }
                reply.extend_from_slice(&chunk);
            }
            parse_reply(&reply)
        };
        timeout(CALL_TIMEOUT_MS, call)
            .await
            .map_err(|_| "timeout".to_owned())?
    }

    fn log_error(&self, why: &str) {
        let now = Instant::now();
        let Ok(mut last) = self.last_error_log.lock() else {
            return;
        };
        if last.map_or(false, |t| now.duration_since(t) < ERROR_LOG_INTERVAL) {
            return;
        }
        *last = Some(now);
        log::warn!(
            "AUTHZ: authorization service call failed ({}), {}; next failure logged in {} s at the earliest",
            why,
            if self.fail_closed {
                "refusing connections (AUTHZ_FAIL_CLOSED=Y)"
            } else {
                "letting connections through without permissions"
            },
            ERROR_LOG_INTERVAL.as_secs()
        );
    }
}

/// A failed request, without the URL that reqwest's own message carries.
fn describe(err: reqwest::Error) -> String {
    let what = if err.is_timeout() {
        "timeout"
    } else if err.is_connect() {
        "connect error"
    } else {
        "request failed"
    };
    // the innermost cause, e.g. "Connection refused (os error 111)"
    let mut cause: Option<&dyn std::error::Error> = std::error::Error::source(&err);
    let mut last = None;
    while let Some(c) = cause {
        last = Some(c.to_string());
        cause = c.source();
    }
    match last {
        Some(cause) => format!("{}: {}", what, cause),
        None => what.to_owned(),
    }
}

/// The service's 200 reply.
#[derive(Deserialize)]
struct Reply {
    allow: bool,
    #[serde(default)]
    permissions: Option<serde_json::Value>,
    #[serde(default)]
    reason: Option<String>,
}

/// The decision in a 200 reply. Err: not a valid reply (handled like a failed call).
fn parse_reply(body: &[u8]) -> Result<Verdict, String> {
    let reply: Reply =
        serde_json::from_slice(body).map_err(|e| format!("malformed reply: {}", e))?;
    if !reply.allow {
        let reason = clip(reply.reason.as_deref().unwrap_or_default().trim());
        return Ok(Verdict::Deny(if reason.is_empty() {
            DENIED.to_owned()
        } else {
            reason
        }));
    }
    // a decimal string (a u64 does not fit a JSON number everywhere); a number is accepted
    let permissions = match reply.permissions {
        None | Some(serde_json::Value::Null) => Some(0),
        Some(serde_json::Value::String(s)) if s.trim().is_empty() => Some(0),
        Some(serde_json::Value::String(s)) => s.trim().parse::<u64>().ok(),
        Some(serde_json::Value::Number(n)) => n.as_u64(),
        Some(_) => None,
    };
    match permissions {
        Some(permissions) => Ok(Verdict::Allow(permissions)),
        None => Err("malformed reply: permissions is not a u64".to_owned()),
    }
}

/// At most MAX_REASON_LEN bytes, cut at a character boundary.
fn clip(s: &str) -> String {
    let mut end = s.len().min(MAX_REASON_LEN);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_owned()
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct Key {
    target_id: String,
    token: [u8; 32],
    conn_type: i32,
    controller_ip: IpAddr,
}

impl Key {
    fn new(attempt: &Attempt<'_>) -> Self {
        let mut token = [0u8; 32];
        token.copy_from_slice(&Sha256::digest(attempt.token.as_bytes()));
        Self {
            target_id: attempt.target_id.to_owned(),
            token,
            conn_type: attempt.conn_type,
            controller_ip: attempt.controller_ip,
        }
    }
}

/// Decisions for CACHE_TTL, at most CACHE_MAX of them.
#[derive(Default)]
struct Cache {
    map: HashMap<Key, (Instant, Verdict)>,
}

impl Cache {
    fn get(&mut self, key: &Key, now: Instant) -> Option<Verdict> {
        let (at, verdict) = self.map.get(key)?;
        if now.saturating_duration_since(*at) < CACHE_TTL {
            return Some(verdict.clone());
        }
        self.map.remove(key);
        None
    }

    fn insert(&mut self, key: Key, verdict: Verdict, now: Instant) {
        if self.map.len() >= CACHE_MAX && !self.map.contains_key(&key) {
            self.map
                .retain(|_, (at, _)| now.saturating_duration_since(*at) < CACHE_TTL);
            if self.map.len() >= CACHE_MAX {
                let oldest = self
                    .map
                    .iter()
                    .min_by_key(|(_, (at, _))| *at)
                    .map(|(k, _)| k.clone());
                if let Some(oldest) = oldest {
                    self.map.remove(&oldest);
                }
            }
        }
        self.map.insert(key, (now, verdict));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hbb_common::{
        rendezvous_proto::{FetchLocalAddr, PunchHole, RequestRelay},
        tokio::{
            self,
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpListener,
        },
    };
    use std::sync::Arc;

    fn attempt<'a>(token: &'a str, conn_type: i32) -> Attempt<'a> {
        Attempt {
            target_id: "peer123",
            token,
            conn_type,
            controller_ip: "198.51.100.1".parse().unwrap(),
            kind: Kind::PunchHole,
        }
    }

    #[test]
    fn replies() {
        let ok = |body: &str| parse_reply(body.as_bytes());
        assert_eq!(ok(r#"{"allow":true}"#), Ok(Verdict::Allow(0)));
        assert_eq!(ok(r#"{"allow":true,"permissions":"0"}"#), Ok(Verdict::Allow(0)));
        assert_eq!(ok(r#"{"allow":true,"permissions":null}"#), Ok(Verdict::Allow(0)));
        assert_eq!(ok(r#"{"allow":true,"permissions":"66"}"#), Ok(Verdict::Allow(66)));
        assert_eq!(
            ok(r#"{"allow":true,"permissions":"18446744073709551615","reason":"x"}"#),
            Ok(Verdict::Allow(u64::MAX))
        );
        assert_eq!(ok(r#"{"allow":true,"permissions":66}"#), Ok(Verdict::Allow(66)));
        // unknown fields are ignored
        assert_eq!(ok(r#"{"allow":true,"ttl":5}"#), Ok(Verdict::Allow(0)));
        // refusals: the service's reason, else the default
        assert_eq!(
            ok(r#"{"allow":false,"reason":" Not your device "}"#),
            Ok(Verdict::Deny("Not your device".to_owned()))
        );
        assert_eq!(ok(r#"{"allow":false}"#), Ok(Verdict::Deny(DENIED.to_owned())));
        assert_eq!(
            ok(r#"{"allow":false,"reason":"  ","permissions":"66"}"#),
            Ok(Verdict::Deny(DENIED.to_owned()))
        );
        let long = format!(r#"{{"allow":false,"reason":"{}"}}"#, "ж".repeat(300));
        match ok(&long) {
            Ok(Verdict::Deny(reason)) => {
                assert!(reason.len() <= MAX_REASON_LEN && reason.len() >= MAX_REASON_LEN - 1);
                assert!(reason.chars().all(|c| c == 'ж'));
            }
            other => panic!("{other:?}"),
        }
        // anything else is a failed call
        for bad in [
            "",
            "null",
            "not json",
            "{}",
            r#"{"allow":"yes"}"#,
            r#"{"allow":true,"permissions":"abc"}"#,
            r#"{"allow":true,"permissions":"-1"}"#,
            r#"{"allow":true,"permissions":-1}"#,
            r#"{"allow":true,"permissions":1.5}"#,
            r#"{"allow":true,"permissions":"18446744073709551616"}"#,
            r#"{"allow":true,"permissions":[1]}"#,
        ] {
            assert!(parse_reply(bad.as_bytes()).is_err(), "{bad}");
        }
    }

    #[test]
    fn refusal_mapping() {
        match refusal(Kind::PunchHole, "no".to_owned()).union {
            Some(rendezvous_message::Union::PunchHoleResponse(r)) => {
                assert_eq!(r.other_failure, "no");
                assert!(r.socket_addr.is_empty() && r.pk.is_empty());
            }
            other => panic!("{other:?}"),
        }
        match refusal(Kind::RequestRelay, "no".to_owned()).union {
            Some(rendezvous_message::Union::RelayResponse(r)) => {
                assert_eq!(r.refuse_reason, "no");
                assert!(r.socket_addr.is_empty() && r.uuid.is_empty());
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn permissions_set_and_cleared() {
        let permissions = |msg: &RendezvousMessage| {
            let field = match msg.union.as_ref() {
                Some(rendezvous_message::Union::PunchHole(m)) => &m.control_permissions,
                Some(rendezvous_message::Union::FetchLocalAddr(m)) => &m.control_permissions,
                Some(rendezvous_message::Union::RequestRelay(m)) => &m.control_permissions,
                _ => panic!("unexpected message"),
            };
            field.as_ref().map(|p| p.permissions)
        };
        let mut msgs = [
            RendezvousMessage::new(),
            RendezvousMessage::new(),
            RendezvousMessage::new(),
        ];
        msgs[0].set_punch_hole(PunchHole::default());
        msgs[1].set_fetch_local_addr(FetchLocalAddr::default());
        msgs[2].set_request_relay(RequestRelay::default());
        for msg in msgs.iter_mut() {
            set_permissions(msg, 66);
            assert_eq!(permissions(msg), Some(66));
            set_permissions(msg, 0);
            assert_eq!(permissions(msg), None);
        }
        // other messages are left alone
        let mut other = refusal(Kind::PunchHole, "no".to_owned());
        set_permissions(&mut other, 66);
        assert_eq!(other, refusal(Kind::PunchHole, "no".to_owned()));
    }

    #[test]
    fn cache_expires_and_tells_attempts_apart() {
        let mut cache = Cache::default();
        let t0 = Instant::now();
        let key = Key::new(&attempt("tok", 0));
        cache.insert(key.clone(), Verdict::Allow(66), t0);
        assert_eq!(cache.get(&key, t0 + Duration::from_secs(14)), Some(Verdict::Allow(66)));
        // the kind is not part of the key: a relay request after a punch request hits
        let relay = Attempt {
            kind: Kind::RequestRelay,
            ..attempt("tok", 0)
        };
        assert_eq!(cache.get(&Key::new(&relay), t0), Some(Verdict::Allow(66)));
        // everything else is
        let other_ip = Attempt {
            controller_ip: "198.51.100.2".parse().unwrap(),
            ..attempt("tok", 0)
        };
        let other_peer = Attempt {
            target_id: "peer124",
            ..attempt("tok", 0)
        };
        for other in [attempt("tok2", 0), attempt("", 0), attempt("tok", 1), other_ip, other_peer] {
            assert_eq!(cache.get(&Key::new(&other), t0), None);
        }
        // the token is kept as a hash only
        assert_eq!(key.token[..], Sha256::digest(b"tok")[..]);
        // expired: gone
        assert_eq!(cache.get(&key, t0 + CACHE_TTL), None);
        assert!(cache.map.is_empty());
    }

    #[test]
    fn cache_is_bounded() {
        let mut cache = Cache::default();
        let t0 = Instant::now();
        let tokens: Vec<String> = (0..=CACHE_MAX).map(|i| format!("t{i}")).collect();
        for (i, token) in tokens.iter().take(CACHE_MAX).enumerate() {
            let at = t0 + Duration::from_micros(i as u64);
            cache.insert(Key::new(&attempt(token, 0)), Verdict::Allow(1), at);
        }
        assert_eq!(cache.map.len(), CACHE_MAX);
        // all fresh: the oldest makes room
        let now = t0 + Duration::from_secs(1);
        cache.insert(Key::new(&attempt(&tokens[CACHE_MAX], 0)), Verdict::Allow(2), now);
        assert_eq!(cache.map.len(), CACHE_MAX);
        assert_eq!(cache.get(&Key::new(&attempt(&tokens[0], 0)), now), None);
        assert_eq!(
            cache.get(&Key::new(&attempt(&tokens[1], 0)), now),
            Some(Verdict::Allow(1))
        );
        // expired ones go first, all at once (all but the one inserted at `now`)
        let later = t0 + CACHE_TTL + Duration::from_millis(500);
        cache.insert(Key::new(&attempt("fresh", 0)), Verdict::Allow(3), later);
        assert_eq!(cache.map.len(), 2);
        // replacing an entry never evicts another one
        cache.insert(Key::new(&attempt("fresh", 0)), Verdict::Allow(4), later);
        assert_eq!(cache.get(&Key::new(&attempt("fresh", 0)), later), Some(Verdict::Allow(4)));
    }

    /// A one-shot-per-connection HTTP server: replies `status`/`body` to each request
    /// and keeps the raw requests.
    async fn stub(status: u16, body: &'static str) -> (String, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/authorize", listener.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen2 = seen.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = listener.accept().await else {
                    return;
                };
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                // headers, then a body of Content-Length bytes
                loop {
                    let n = s.read(&mut tmp).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                    let text = String::from_utf8_lossy(&buf).to_string();
                    if let Some(end) = text.find("\r\n\r\n") {
                        let len = text[..end]
                            .lines()
                            .find_map(|l| {
                                let (k, v) = l.split_once(':')?;
                                k.eq_ignore_ascii_case("content-length")
                                    .then(|| v.trim().parse::<usize>().ok())?
                            })
                            .unwrap_or(0);
                        if buf.len() >= end + 4 + len {
                            break;
                        }
                    }
                }
                seen2
                    .lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&buf).to_string());
                let out = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                s.write_all(out.as_bytes()).await.ok();
            }
        });
        (url, seen)
    }

    #[tokio::test]
    async fn calls_the_service_once_per_decision() {
        let (url, seen) = stub(200, r#"{"allow":true,"permissions":"66"}"#).await;
        let authz = Authz::new(&url, "s3cret".to_owned(), false).unwrap();
        let a = Attempt {
            controller_ip: "::1".parse().unwrap(),
            ..attempt("tok", 1)
        };
        assert_eq!(authz.check(&a).await, Verdict::Allow(66));
        assert_eq!(authz.check(&a).await, Verdict::Allow(66));
        let seen = seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 1, "the second decision was not cached");
        let req = &seen[0];
        assert!(req.starts_with("POST /authorize HTTP/1.1\r\n"), "{req}");
        let lower = req.to_ascii_lowercase();
        assert!(lower.contains("\r\nauthorization: bearer s3cret\r\n"), "{req}");
        assert!(lower.contains("\r\ncontent-type: application/json\r\n"), "{req}");
        let body: serde_json::Value =
            serde_json::from_str(&req[req.find("\r\n\r\n").unwrap() + 4..]).unwrap();
        assert_eq!(
            body,
            serde_json::json!({
                "target_id": "peer123",
                "token": "tok",
                "conn_type": 1,
                "controller_ip": "::1",
                "kind": "punch_hole",
            })
        );
    }

    #[tokio::test]
    async fn failed_calls_fail_open_or_closed_and_are_not_cached() {
        for (status, body) in [(500, r#"{"allow":true}"#), (200, "not json"), (302, "")] {
            let (url, seen) = stub(status, body).await;
            let open = Authz::new(&url, String::new(), false).unwrap();
            let closed = Authz::new(&url, String::new(), true).unwrap();
            let a = attempt("tok", 0);
            assert_eq!(open.check(&a).await, Verdict::Allow(0), "{status} {body}");
            assert_eq!(
                closed.check(&a).await,
                Verdict::Deny(UNAVAILABLE.to_owned()),
                "{status} {body}"
            );
            assert_eq!(closed.check(&a).await, Verdict::Deny(UNAVAILABLE.to_owned()));
            assert_eq!(seen.lock().unwrap().len(), 3, "a failure was cached");
            // no secret: no Authorization header
            assert!(!seen.lock().unwrap()[0]
                .to_ascii_lowercase()
                .contains("authorization:"));
        }
        // nothing listening
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let url = format!("http://127.0.0.1:{port}/authorize");
        let a = attempt("tok", 0);
        let open = Authz::new(&url, "s".to_owned(), false).unwrap();
        assert_eq!(open.check(&a).await, Verdict::Allow(0));
        let closed = Authz::new(&url, "s".to_owned(), true).unwrap();
        assert_eq!(closed.check(&a).await, Verdict::Deny(UNAVAILABLE.to_owned()));
    }

    #[tokio::test]
    async fn a_hanging_service_costs_at_most_the_timeout() {
        // accepts, never answers
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/authorize", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((s, _)) = listener.accept().await {
                held.push(s);
            }
        });
        let closed = Authz::new(&url, "s".to_owned(), true).unwrap();
        let start = Instant::now();
        assert_eq!(
            closed.check(&attempt("tok", 0)).await,
            Verdict::Deny(UNAVAILABLE.to_owned())
        );
        let took = start.elapsed();
        assert!(took >= Duration::from_millis(CALL_TIMEOUT_MS - 100), "{took:?}");
        assert!(took < Duration::from_millis(CALL_TIMEOUT_MS + 1500), "{took:?}");
    }

    #[test]
    fn urls() {
        assert!(Authz::new("ftp://127.0.0.1/x", String::new(), false).is_err());
        assert!(Authz::new("127.0.0.1:21114/x", String::new(), false).is_err());
        assert!(Authz::new("not a url", String::new(), false).is_err());
        let authz = Authz::new(
            "https://user:pw@panel.example.com:8443/internal/hbbs/authorize?k=v#f",
            String::new(),
            false,
        )
        .unwrap();
        assert_eq!(
            url_for_log(&authz.url),
            "https://panel.example.com:8443/internal/hbbs/authorize"
        );
    }
}
