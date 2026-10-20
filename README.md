# rustdesk-server (bropines fork)

hbbs/hbbr for [RD Panel](https://github.com/bropines/rdpanel), an API server and admin
panel for RustDesk. This fork is based on
[rustdesk/rustdesk-server](https://github.com/rustdesk/rustdesk-server) **1.1.17**
(upstream `master`) and includes the API-server patches from
[lejianwen/rustdesk-server](https://github.com/lejianwen/rustdesk-server) (`forapi`).
It is not an official RustDesk project.

Default branch: **`rdpanel`**. RD Panel's container image pins a commit of this branch.

## What differs from upstream

| feature | how to enable | origin |
|---|---|---|
| Require a signed-in RustDesk client to connect | `MUST_LOGIN=Y` (or `--must-login Y`, admin command `must-login Y\|N`) | lejianwen |
| Validate client tokens as JWT (HS256) | `RUSTDESK_API_JWT_KEY=<same key as the API server>` | lejianwen |
| No connection timeouts for clients signed in to an API server | always on | lejianwen |
| WebSocket clients (client ≥ 1.4.1) | ports 21118/21119 | lejianwen |
| Keepalive for TCP/WebSocket rendezvous clients | `TCP_KEEPALIVE=Y` (or `--tcp-keepalive Y`, admin command `tcp-keepalive Y\|N`) | this fork |
| WebRTC signaling for RustDesk ≥ 1.5.0 (SDP offer/answer, trickle ICE) | `WEBRTC=Y` (or `--webrtc Y`, admin command `webrtc Y\|N`) | this fork |
| Forward `RequestRelay` to peers registered over WebSocket | `WS_PEERS=Y` (or `--ws-peers Y`, admin command `ws-peers Y\|N`) | this fork |
| Separate relays for WebSocket (browser) clients | `WS_RELAY_SERVERS=<host:port,...>` (or `--ws-relay-servers`) | this fork |
| Relay selection by client IP prefix | a `relay_map.txt` file next to hbbs (admin command `reload-geo`) | this fork |
| Real client IPs behind a reverse proxy on another host (WebSocket port) | `TRUSTED_PROXIES=<IPs/CIDRs>` (or `--trusted-proxies`) | this fork |
| Ask an HTTP service (e.g. RD Panel) before forwarding each connection attempt; it can refuse it or set the peer's permissions | `AUTHZ_URL=<url>` (or `--authz-url`), with `AUTHZ_SECRET_FILE` / `AUTHZ_SECRET` and `AUTHZ_FAIL_CLOSED` | this fork |
| Hardening: no secrets in logs, no panic on a bad `KeyExchange`; see [Security](#security) | always on | this fork |

Everything else behaves like upstream. Where this fork changes behaviour, the change is
opt-in and off by default.

### `TCP_KEEPALIVE`

Clients that use "Use WebSocket"/TCP mode, or that fall back to it when UDP is blocked,
register once and then wait for the server. Upstream hbbs sends them nothing, so they
show as offline between re-registrations, which happen about every 90 s. With
`TCP_KEEPALIVE=Y`, hbbs sends an empty frame every 12 s to registered TCP/WS
connections. Idle connections that never register are still closed after 30 s.
WebSocket clients always connect through the relay; size the relay bandwidth for that.

### `WEBRTC`

RustDesk 1.5.0 can open a WebRTC (ICE + DTLS) transport next to the usual TCP/UDP punch
and relay, when the client has `enable-webrtc` on. hbbs only carries the signaling; the
media path is peer-to-peer or through the TURN servers in the clients' `ice-servers`
option. Upstream hbbs drops the WebRTC fields, so clients fall back to the classic
transports. With `WEBRTC=Y` this hbbs forwards:

| from → to | message (field) |
|---|---|
| controller → controlled | `PunchHoleRequest.webrtc_sdp_offer` → `PunchHole.webrtc_sdp_offer` (plus `force_relay`, which sets the answer's ICE policy) |
| controlled → controller | `PunchHoleSent.webrtc_sdp_answer` → `PunchHoleResponse.webrtc_sdp_answer`; `RelayResponse.webrtc_sdp_answer` (forwarded as upstream does) |
| controlled → controller | `IceCandidate` with `socket_addr` (from `PunchHole`), sent over TCP; delivered on the controller's punch connection |
| controller → controlled | `IceCandidate` with `id`, sent on the punch connection; delivered over the peer's WebSocket or UDP registration |

Candidates are forwarded only along a route that hbbs created when it forwarded an
offer, i.e. after the key, `MUST_LOGIN` and online checks; at most 256 per direction,
for 60 s, and the controller's punch connection is kept for the trickle instead of being
consumed by the response. Offers are dropped when `ALWAYS_USE_RELAY=Y`, because a
WebRTC pair can be direct. With `WEBRTC` off nothing changes: the fields are dropped
and an `IceCandidate` closes the connection, as upstream does.

Behind one public IP upstream sends the controlled peer `FetchLocalAddr`, which has no
offer field. With `WEBRTC=Y`, a request that carries an offer gets a `PunchHole` with the
offer instead; the client sends its TCP punch in a separate request without an offer,
which still gets `FetchLocalAddr`, so the LAN path stays.

With `RUST_LOG=info,hbbs=debug` hbbs logs each offer, answer and ICE candidate it
forwards or drops (with the reason), and route creation and expiry. At `info` it logs one
line per WebRTC session when it ends: offers forwarded, which message carried the answer,
and candidates each way. Only sizes and counts are logged, never SDP, candidates or keys.
No `WebRTC offer` line for a connection means the controller sent no offer: the client
only offers with "Enable WebRTC" on, never through a SOCKS proxy, and not when the peer
is set to "Always connect via relay" (`force-always-relay`) unless its `ice-servers`
include a TURN server.

### `WS_PEERS`

Peers that register over WebSocket (RustDesk clients with "Use WebSocket") get
`PunchHole` on that connection. With `WS_PEERS=Y` a `RequestRelay` for such a peer (e.g.
from RD Panel's web client) is sent there too; by default it goes over UDP to the
peer's address, as upstream.

### `WS_RELAY_SERVERS`

Browser clients can only reach a relay that serves TLS WebSocket, usually just the hbbr
behind the panel's reverse proxy, while the relay list (`-r` / `RELAY`) may include
remote relays they cannot reach. With `WS_RELAY_SERVERS=<host:port>[,<host:port>...]`
a controller connected over WebSocket gets a relay from that list (in rotation)
instead of the normal relay choice and prefix routing: in the `PunchHole` /
`FetchLocalAddr` sent to the peer for its punch request, and in the `RequestRelay`
forwarded for it (a relay it asked for is kept when it is in the list, otherwise
replaced). Empty (default): WebSocket clients get the normal relay choice, as
upstream. The list is read at start.

### `TRUSTED_PROXIES`

The WebSocket port (21118) takes the client IP from `X-Real-IP` (else the rightmost
`X-Forwarded-For` hop that is not a trusted proxy) only when the connection comes from
loopback or from an address in `TRUSTED_PROXIES` (IPs or CIDRs, comma separated, e.g.
`TRUSTED_PROXIES=172.16.0.0/12`). From anyone else the headers are ignored, as are
loopback, unspecified and unparsable values. Set it when the reverse proxy in front of
the WebSocket port runs on another host or container; otherwise all WebSocket clients
show the proxy's IP (and share its IP-based limits). RD Panel's built-in `/ws/id`
proxy connects over loopback and needs nothing.

### `AUTHZ_URL`

Upstream hbbs forwards every connection attempt that passes the licence key and
`MUST_LOGIN` checks; whether it is accepted is then up to the controlled device. With
`AUTHZ_URL=<http(s) URL>` (or `--authz-url`), hbbs first asks that service about each
`PunchHoleRequest` and each client `RequestRelay` it is about to forward to an online
peer (after the key, `MUST_LOGIN` and online checks):

```http
POST <AUTHZ_URL>
Authorization: Bearer <secret>
Content-Type: application/json

{"target_id":"<peer id>","token":"<controller's token, may be empty>","conn_type":0,"controller_ip":"203.0.113.5","kind":"punch_hole"}
```

`conn_type` is the request's `ConnType` (0 default, 1 file transfer, 2 port forward,
3 RDP, 4 view camera, 5 terminal), `controller_ip` the address hbbs resolved for the
controller (see `TRUSTED_PROXIES`), `kind` is `punch_hole` or `request_relay`. The
service answers `200` with

```json
{"allow": true, "permissions": "66", "reason": ""}
```

- `allow: false`: the attempt is refused with `reason` (default "Access denied by the
  server policy"), the way the other checks refuse (`PunchHoleResponse.other_failure`
  for a punch request, `RelayResponse.refuse_reason` for a relay request); nothing
  reaches the peer.
- `allow: true`: forwarded as usual. A non-zero `permissions` (a u64 as a decimal
  string; absent or `"0"`: none) is set as `ControlPermissions` on the `PunchHole`,
  `FetchLocalAddr` or `RequestRelay` the peer gets for this attempt; RustDesk clients
  apply it over the device owner's local settings. The layout is RustDesk's: 2 bits
  per `ControlPermissions.Permission` value `p`, at bit `2*p`, `1` = disable,
  `2` = enable, `0` = not set (keyboard 0, remote_printer 1, clipboard 2, file 3,
  audio 4, camera 5, terminal 6, tunnel 7, restart 8, recording 9, block_input 10,
  remote_modify 11, privacy_mode 12, usb 13). `66` = keyboard enabled (`2 << 0`) and
  file transfer disabled (`1 << 6`).

Decisions are cached for 15 s per peer, token, `conn_type` and controller IP (at most
10 000), so the `RequestRelay` that follows a failed direct connection costs no second
call, and a changed decision applies within 15 s. A call that fails (2 s timeout,
connection error, a status other than 200, a malformed reply) is not cached and by
default **fails open**: the attempt goes through without permissions, as with
`AUTHZ_URL` unset. With `AUTHZ_FAIL_CLOSED=Y` (or `--authz-fail-closed Y`) it is refused
("Authorization service unavailable"). Failures are logged at warn level, at most once
per 30 s; with `RUST_LOG=info,hbbs=debug` every decision is logged.

The secret is read from `AUTHZ_SECRET_FILE` (or `--authz-secret-file`), else
`AUTHZ_SECRET` (or `--authz-secret`), whitespace trimmed. It is sent to `AUTHZ_URL`
only (no proxy from `HTTP(S)_PROXY`, no redirects) and never logged, nor are tokens.
An invalid `AUTHZ_URL` or an unreadable secret file stops hbbs at start. The settings
are read at start. Empty `AUTHZ_URL` (default): no calls, upstream behaviour.

### `relay_map.txt` (relay by IP prefix)

When a file `relay_map.txt` exists in hbbs' working directory (the data directory),
hbbs picks the relay for a connection by IP prefix instead of round robin: the
controller's IP is matched first, then the controlled peer's, longest prefix first.
One rule per line, `#` starts a comment:

```text
# <cidr>          <relay>[,<relay>...]   (each written as in -r / RELAY)
185.162.0.0/16    ru-relay.example.com:21117
10.0.0.0/8        eu-relay.example.com,eu-relay2.example.com
2001:db8::/32     eu-relay.example.com
```

Relays that are not in the relay list (or currently unreachable) are skipped; several
relays in a rule are used round robin; with no match the usual round robin over all
relays applies. The file is read at start and by the admin command `reload-geo` (`rg`);
malformed lines are logged and skipped. `test-geo <controller-ip> <peer-ip>` (`tg`) shows the relay a pair gets.

## Security

Changes from upstream that are always on, because they close holes rather than add
features:

- TCP/WebSocket rendezvous: a `RegisterPeer` (which has no uuid) only refreshes the id
  that connection registered with an accepted, uuid-checked `RegisterPk`; anything else
  is answered with `request_pk` and the peer's address stays where it is. With
  `TCP_KEEPALIVE`, only such a registration is kept online by its keepalives.
- `RequestRelay` from a client gets the checks `PunchHoleRequest` has: `MUST_LOGIN`
  (and the JWT check), and the licence key. RustDesk clients send the key in
  `PunchHoleRequest` but not in the `RequestRelay` that follows a failed direct
  connection, so a request without a key is accepted from an IP that passed the key
  check for that peer in the last 120 s. Only online peers are asked, the controller's
  token is not forwarded to the peer, and oversized requests are refused.
- A client's `RequestRelay` reaches the peer without its `control_permissions` and
  `controlled_context`. RustDesk clients apply `ControlPermissions` from the rendezvous
  server over the device owner's local settings ("enable" grants), so with upstream,
  which forwards both as sent, a controller can grant itself e.g. keyboard, file
  transfer or terminal access. Only hbbs sets them now (see `AUTHZ_URL`); `PunchHole`
  and `FetchLocalAddr` are built by hbbs and never carried the controller's.
- WebSocket client addresses: see `TRUSTED_PROXIES`. Every WebSocket connection keeps
  its own port, so clients behind one IP no longer share an address.
- Each TCP/WebSocket connection has a bounded send queue; a client that does not read
  loses its own messages and is disconnected, and cannot stall delivery to others.
- WebSocket message/frame size: 1 MiB on hbbs, 16 MiB on hbbr.

## Usage

The easiest way is the RD Panel all-in-one image (hbbs + hbbr + panel):

```sh
docker pull ghcr.io/bropines/rdpanel:latest
```

See the [RD Panel deployment guide](https://github.com/bropines/rdpanel/blob/main/docs/deploy.md).
The binaries accept the same options as upstream; see the
[RustDesk self-host docs](https://rustdesk.com/docs/en/self-host/) and upstream's
[configuration & environment variables](docs/environment-variables.md) reference
(bind address, `MAX_PUNCH_REQUESTS`, database and relay tuning).

## Building

```sh
git clone --recurse-submodules https://github.com/bropines/rustdesk-server
cd rustdesk-server
cargo build --release --bin hbbs --bin hbbr --bin rustdesk-utils
```

Static musl builds for the image use `cross` (see the RD Panel `image` workflow).

## Branches

- `rdpanel`: maintained branch (upstream master + lejianwen API patches + this fork's fixes).
- `merge-upstream-1.1.16`: the branch the 1.1.16 work was done on; kept because older
  RD Panel builds reference its commits.
- `forapi`, `master`, `0.0.9`, `0.1.x`: inherited from lejianwen and upstream, not maintained.

## License

AGPL-3.0, same as upstream (see [LICENSE](LICENSE)).
