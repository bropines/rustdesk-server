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
| Hardening: no secrets in logs, no panic on a bad `KeyExchange` | always on | this fork |

Everything else behaves like upstream. Where this fork changes behaviour, the change is
opt-in and off by default.

### `TCP_KEEPALIVE`

Clients that use "Use WebSocket"/TCP mode, or that fall back to it when UDP is blocked,
register once and then wait for the server. Upstream hbbs sends them nothing, so they
show as offline between re-registrations, which happen about every 90 s. With
`TCP_KEEPALIVE=Y`, hbbs sends an empty frame every 12 s to registered TCP/WS
connections. Idle connections that never register are still closed after 30 s.
WebSocket clients always connect through the relay; size the relay bandwidth for that.

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
